import sqlite3
import unittest

from hydrate_and_verify import (
    compute_cli_risk_score,
    compute_termination_exposure_inr,
    init_db,
    run_smoke_test,
    select_healthy_clis,
)


class TestScoring(unittest.TestCase):
    def test_compute_termination_exposure_inr(self):
        self.assertEqual(compute_termination_exposure_inr([0, 1, 60, 61]), 0.20)

    def test_compute_cli_risk_score(self):
        self.assertEqual(compute_cli_risk_score(0, 0, 0, 0), 0.0)
        self.assertEqual(compute_cli_risk_score(1, 2, 1, 3), 100.0)
        self.assertEqual(compute_cli_risk_score(0, 1, 0, 0), 25.0)

    def test_select_healthy_clis_respects_now_ts_and_10d_window(self) -> None:
        conn = sqlite3.connect(":memory:")
        init_db(conn)
        now_ts = 1763000000
        # CLI 1: Active DLT, 2 complaints aged out at now_ts - 864001 (11 days ago) + 1 compliant call
        conn.execute(
            "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("DLT-1", "+911600412900", "JIO", "160_SERVICE_BFSI", 1, "ACTIVE", 1758153600, 1789689600),
        )
        # CLI 2: Expired DLT at now_ts - 1
        conn.execute(
            "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("DLT-2", "+911600999999", "AIRTEL", "160_SERVICE_BFSI", 1, "ACTIVE", 1758153600, now_ts - 1),
        )
        conn.execute(
            "INSERT INTO cdr_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("old_c1", "+911600412900", "r1", "SERVICE_REMINDER", now_ts - 864001, 30, 1, "comp_a", 1),
        )
        conn.execute(
            "INSERT INTO cdr_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("old_c2", "+911600412900", "r2", "SERVICE_REMINDER", now_ts - 864002, 30, 1, "comp_b", 1),
        )
        conn.execute(
            "INSERT INTO cdr_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("recent_ok", "+911600412900", "r3", "SERVICE_REMINDER", now_ts - 3600, 45, 0, None, 0),
        )
        healthy = select_healthy_clis(conn, now_ts=now_ts)
        self.assertEqual([row["cli_e164"] for row in healthy], ["+911600412900"])

    def test_run_smoke_test(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "smoke_test_audit.jsonl")
            result = run_smoke_test(200, out)
        self.assertEqual(result["rows_evaluated"], 200)
        self.assertEqual(result["rule_precision"], 1.0)


if __name__ == "__main__":
    unittest.main()
