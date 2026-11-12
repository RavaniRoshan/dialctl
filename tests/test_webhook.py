import concurrent.futures
import sqlite3
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from hydrate_and_verify import init_db, verify_hash_chain
from middleware import ComplianceBlockError, SarvamExotelComplianceMiddleware
from server import ComplianceGateState, handle_pre_dial_payload


class TestWebhook(unittest.TestCase):
    def setUp(self):
        self.state = ComplianceGateState.create_with_sample_fixture(secret_key="test-secret")

    def test_pre_dial_latency_under_5ms_and_blocks_undeclared(self):
        state = ComplianceGateState.create_with_sample_fixture(secret_key="test-secret")
        payload = {
            "call_sid": "c_allow",
            "cli_e164": "+911600412900",
            "customer_phone": "+919876543210",
            "call_intent": "INQUIRY_FOLLOWUP",
            "call_ts": 1762936200,
        }
        start = time.perf_counter()
        status, record = handle_pre_dial_payload(state, payload)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.assertEqual(status, 200)
        self.assertEqual(record["decision"], "ALLOW")
        self.assertLess(elapsed_ms, 5.0)

    def test_middleware_prevents_exotel_callback_on_violation(self):
        state = ComplianceGateState.create_with_sample_fixture(secret_key="test-secret")
        mw = SarvamExotelComplianceMiddleware(state)
        dialed = False

        def dial_callback():
            nonlocal dialed
            dialed = True
            return "dialed"

        with self.assertRaises(ComplianceBlockError) as ctx:
            mw.dial(
                call_sid="c_block",
                cli_e164="+919811122233",
                customer_phone="+919876543210",
                call_intent="PROMOTIONAL",
                call_ts=1762936200,
                dial_callback=dial_callback,
            )
        self.assertIn("R1_CLI_DECLARED", ctx.exception.failed_rules)
        self.assertFalse(dialed)

    def test_concurrent_pre_dial_chain_integrity(self):
        state = ComplianceGateState.create_with_sample_fixture(secret_key="test-secret")
        n = 40

        def worker(i):
            payload = {
                "call_sid": f"c_concurrent_{i}",
                "cli_e164": "+911600412900",
                "customer_phone": "+919876543210",
                "call_intent": "INQUIRY_FOLLOWUP",
                "call_ts": 1762936200,
            }
            status, record = handle_pre_dial_payload(state, payload)
            return status, record

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker, i) for i in range(n)]
            results = [f.result() for f in futures]

        records = [record for _status, record in results]
        seq_nos = [r["seq_no"] for r in records]
        self.assertEqual(len(set(seq_nos)), n)
        self.assertEqual(sorted(seq_nos), list(range(1, n + 1)))
        records_in_seq_order = sorted(records, key=lambda r: r["seq_no"])
        self.assertEqual(verify_hash_chain(records_in_seq_order), (True, "OK"))


    def test_http_400_preserves_seq_no_and_chain_state(self) -> None:
        initial_seq = self.state.seq_no
        initial_hash = self.state.last_attestation_hash
        status, body = handle_pre_dial_payload(self.state, {"call_sid": "missing_fields_only"})
        self.assertEqual(status, 400)
        self.assertIn("error", body)
        self.assertEqual(self.state.seq_no, initial_seq)
        self.assertEqual(self.state.last_attestation_hash, initial_hash)

    def test_get_root_serves_ui_html(self) -> None:
        from server import _ComplianceHandler

        _ComplianceHandler.state = self.state
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ComplianceHandler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("text/html", resp.headers.get("Content-Type", ""))
                body = resp.read().decode("utf-8")
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertIn("trai_a2p_audit_v1", body)
        self.assertIn("sha256FallbackHex", body)


    def test_get_healthy_clis_endpoint_shape_and_no_cli_registry(self) -> None:
        import json
        import urllib.request
        from server import _ComplianceHandler

        # No dead cli_registry table may exist in the schema.
        conn = sqlite3.connect(":memory:")
        init_db(conn)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        self.assertNotIn("cli_registry", tables)

        _ComplianceHandler.state = self.state
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ComplianceHandler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/v1/cli/healthy?now_ts=1762936200", timeout=5
            ) as resp:
                self.assertEqual(resp.status, 200)
                payload = json.loads(resp.read().decode("utf-8"))
        finally:
            httpd.shutdown()
            httpd.server_close()

        self.assertIsInstance(payload, dict)
        self.assertIn("healthy_clis", payload)
        self.assertIsInstance(payload["healthy_clis"], list)


if __name__ == "__main__":
    unittest.main()


class TestChainOwnership(unittest.TestCase):
    """The sequence and hash chain are an invariant of the state object, not
    something each caller re-implements. The state exposes one decide() that
    locks, evaluates, and appends; callers cannot forget a step."""

    def setUp(self):
        self.state = ComplianceGateState.create_with_sample_fixture(secret_key="test-secret")

    def test_decide_advances_the_chain(self):
        payload = {
            "call_sid": "c1",
            "cli_e164": "+911600412900",
            "customer_phone": "+919876543210",
            "call_intent": "INQUIRY_FOLLOWUP",
            "call_ts": 1762936200,
        }
        rec = self.state.decide(payload)
        self.assertEqual(rec["seq_no"], 1)
        self.assertEqual(self.state.seq_no, 1)
        self.assertEqual(self.state.last_attestation_hash, rec["attestation_hash"])

        rec2 = self.state.decide(dict(payload, call_sid="c2"))
        self.assertEqual(rec2["seq_no"], 2)
        self.assertEqual(rec2["prev_hash"], rec["attestation_hash"])

    def test_decide_returns_a_valid_chain(self):
        payload = {
            "call_sid": "c1",
            "cli_e164": "+911600412900",
            "customer_phone": "+919876543210",
            "call_intent": "INQUIRY_FOLLOWUP",
            "call_ts": 1762936200,
        }
        records = [self.state.decide(dict(payload, call_sid=f"c{i}")) for i in range(5)]
        self.assertEqual(verify_hash_chain(records), (True, "OK"))

    def test_decide_does_not_mutate_on_invalid_payload(self):
        before = (self.state.seq_no, self.state.last_attestation_hash)
        rec = self.state.decide({"call_sid": "bad"})
        self.assertEqual(rec["seq_no"], 0)  # untouched, not a real record
        self.assertEqual((self.state.seq_no, self.state.last_attestation_hash), before)
