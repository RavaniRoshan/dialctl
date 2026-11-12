import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

HTML = Path(__file__).resolve().parent.parent / "web" / "index.html"


def _run_node(script: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
        fh.write(script)
        path = fh.name
    try:
        proc = subprocess.run(["node", path], capture_output=True, text=True, timeout=30)
    finally:
        Path(path).unlink(missing_ok=True)
    if proc.returncode != 0:
        raise AssertionError(f"node error: {proc.stderr.strip()}")
    return proc.stdout


def _extract_function(text: str, name: str) -> str:
    lines = text.splitlines()
    start = next(
        (i for i, l in enumerate(lines) if l.strip().startswith(f"function {name}")),
        None,
    )
    if start is None:
        raise AssertionError(f"function {name} not found")
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0 and i > start:
            return "\n".join(lines[start : i + 1])
    raise AssertionError(f"function {name} not fully brace-matched")


class TestClearDataFlow(unittest.TestCase):
    """Static checks on the clear-data flow: it must close the DB before delete,
    treat `onblocked` as incomplete, and reopen storage afterwards."""

    def setUp(self):
        self.text = HTML.read_text(encoding="utf-8")

    def test_clear_closes_db_before_delete(self):
        # The clear handler must close the open connection before deleting.
        handler = self._function_body("clearLocalAuditData")
        self.assertIn("db.close()", handler)

    def test_onblocked_not_treated_as_success(self):
        handler = self._function_body("clearLocalAuditData")
        self.assertNotIn("req.onblocked = () => resolve()", handler)
        # onblocked must resolve to an explicit blocked state, not plain success
        self.assertIn("onblocked", handler)
        self.assertIn("blocked", handler)

    def test_clear_handler_reopens_storage(self):
        # After clearing, the handler must reopen the DB for subsequent use.
        self.assertIn("db = await openDb()", self.text)

    def _function_body(self, name):
        lines = self.text.splitlines()
        start = next(i for i, l in enumerate(lines) if l.strip().startswith(f"function {name}"))
        depth = 0
        for i in range(start, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            if depth == 0 and i > start:
                return "\n".join(lines[start : i + 1])
        raise AssertionError(f"function {name} not fully brace-matched")


class TestBrowserScanR3(unittest.TestCase):
    """scanAndAggregate must mirror server evaluate_pre_dial R3 semantics."""

    def setUp(self):
        self.text = HTML.read_text(encoding="utf-8")
        consts = [
            "const R4_WINDOW_SEC = 604800;",
            "const R6_WINDOW_SEC = 864000;",
            "const RULES = {R1_CLI_DECLARED:'',R2_140_160_SERIES:'',R3_ROBO_DND_MODE:'',R4_7DAY_INQUIRY:'',R5_CALL_WINDOW:'',R6_10DAY_CLUSTER:''};",
            "const RULE_IDS = Object.keys(RULES);",
        ]
        helpers = [
            "istSecOfDay",
            "computeRiskScore",
            "terminationExposureInr",
            "sortKeysDeep",
            "r2Passes",
            "r3Trips",
        ]
        self.fn = "\n".join(consts)
        self.fn += "\n" + "\n".join(_extract_function(self.text, h) for h in helpers)
        self.fn += "\n" + _extract_function(self.text, "scanAndAggregate")

    def _run(self, consent_row, extra_cdr=None):
        cdr = {
            "cli_e164": "+911600412900",
            "recipient_hmac": "h1",
            "call_intent": "INQUIRY_FOLLOWUP",
            "call_ts": 1762936200,
            "duration_sec": 45,
            "complaint_flag": 0,
            "operator_ml_flag": 0,
        }
        if extra_cdr:
            cdr.update(extra_cdr)
        dlt = [{
            "cli_e164": "+911600412900",
            "series": "160_SERVICE_BFSI",
            "status": 1,
            "dlt_status": "ACTIVE",
            "valid_from": 1758153600,
            "valid_to": 1789689600,
        }]
        consent = [consent_row] if consent_row is not None else []
        script = (
            self.fn
            + "\nconst out = scanAndAggregate("
            + json.dumps(dlt) + ", " + json.dumps(consent) + ", " + json.dumps([cdr]) + ");\n"
            "const r = out.find(x => x.cli === '+911600412900');\n"
            "process.stdout.write(JSON.stringify({ r3: ((r.failedRulesCounts||{})['R3_ROBO_DND_MODE'] || 0) > 0 }));\n"
        )
        return json.loads(_run_node(script))["r3"]

    def test_missing_consent_trips_r3(self):
        self.assertTrue(self._run(None))

    def test_dnd_robo_block_1_trips_r3(self):
        self.assertTrue(self._run({"recipient_hmac": "h1", "dnd_robo_block": 1, "revoked_ts": ""}))

    def test_revoked_ts_trips_r3(self):
        self.assertTrue(self._run({"recipient_hmac": "h1", "dnd_robo_block": 0, "revoked_ts": "1762000000"}))

    def test_withdrawal_ts_alone_does_not_trip_r3(self):
        # The Python engine treats withdrawal separately from revocation: a
        # withdrawal_ts on its own must not trip R3. The browser now matches.
        self.assertFalse(self._run({"recipient_hmac": "h1", "dnd_robo_block": 0, "withdrawal_ts": "1762000000"}))

    def test_clean_consent_allows(self):
        self.assertFalse(
            self._run({"recipient_hmac": "h1", "dnd_robo_block": 0, "revoked_ts": ""})
        )

    def test_browser_scan_and_aggregate_r3_matches_server_semantics(self):
        # Aggregate assertion named per the plan; exercises all five cases.
        self.assertTrue(self._run(None))
        self.assertTrue(self._run({"recipient_hmac": "h1", "dnd_robo_block": 1, "revoked_ts": ""}))
        self.assertTrue(self._run({"recipient_hmac": "h1", "dnd_robo_block": 0, "revoked_ts": "1762000000"}))
        self.assertFalse(self._run({"recipient_hmac": "h1", "dnd_robo_block": 0, "withdrawal_ts": "1762000000"}))
        self.assertFalse(self._run({"recipient_hmac": "h1", "dnd_robo_block": 0, "revoked_ts": ""}))


if __name__ == "__main__":
    unittest.main()

class TestBrowserRuleConformance(unittest.TestCase):
    """The browser rule helpers must agree with the shared conformance fixture,
    the same file the Python engine runs (tests/test_rule_conformance.py). A
    case added to the fixture must pass in both runtimes, or it is drift."""

    def setUp(self):
        self.text = HTML.read_text(encoding="utf-8")
        self.helpers = "\n".join(
            _extract_function(self.text, name) for name in ("r2Passes", "r3Trips")
        )
        self.cases = json.loads(
            (Path(__file__).parent / "fixtures" / "rule_conformance.json").read_text(
                encoding="utf-8"
            )
        )

    def _eval_case(self, case):
        # r2: needs cli, dlt, intent
        r2_ok = self._run_js(
            self.helpers
            + "\nconst cli = " + json.dumps(case["cli_e164"]) + ";"
            + "const dlt = " + json.dumps(case["declarations"][0] if case["declarations"] else None) + ";"
            + "const intent = " + json.dumps(case["call_intent"].upper()) + ";"
            + "process.stdout.write(String(r2Passes(cli, dlt, intent)));"
        )
        # r3: needs the first consent (or null)
        consent = case["consents"][0] if case["consents"] else None
        r3_trips = self._run_js(
            self.helpers
            + "\nconst consent = " + json.dumps(consent) + ";"
            + "process.stdout.write(String(r3Trips(consent)));"
        )
        return r2_ok.strip() == "true", r3_trips.strip() == "true"

    def _run_js(self, script):
        return _run_node(script)

    def test_browser_r2_and_r3_match_the_conformance_fixture(self):
        for case in self.cases:
            with self.subTest(case=case["name"]):
                r2_ok, r3_trips = self._eval_case(case)
                if "R2_140_160_SERIES" in case.get("expect_failed", []) + case.get("expect_failed_contains", []):
                    self.assertFalse(r2_ok, f"{case['name']}: R2 should fail")
                else:
                    self.assertTrue(r2_ok, f"{case['name']}: R2 should pass")
                if "R3_ROBO_DND_MODE" in case.get("expect_failed", []) + case.get("expect_failed_contains", []):
                    self.assertTrue(r3_trips, f"{case['name']}: R3 should trip")
                else:
                    self.assertFalse(r3_trips, f"{case['name']}: R3 should not trip")
