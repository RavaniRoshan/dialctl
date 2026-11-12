import sqlite3
import unittest

from hydrate_and_verify import GENESIS_HASH, evaluate_pre_dial, hmac_phone, init_db


class TestPreDialRules(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        init_db(self.conn)
        self.conn.execute(
            "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("DLT-JIO-01", "+911600412900", "JIO", "160_SERVICE_BFSI", 1, "ACTIVE", 1758153600, 1789689600),
        )
        self.r_ok = hmac_phone("+919876543210", "secret")
        self.conn.execute(
            "INSERT INTO consent_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("CNS-1", self.r_ok, 0, None, 1762356600, "artifact_sha256_ok", None),
        )

    def test_r4_r5_exact_boundary_seconds(self) -> None:
        # 1762356600 + 604800 == 1762961400 (2026-11-12 21:00:00 IST, exact 7-day & 21:00 boundary)
        allow_rec = evaluate_pre_dial(
            self.conn, "c_allow", "+911600412900", self.r_ok, "INQUIRY_FOLLOWUP", 1762961400, 1, GENESIS_HASH
        )
        self.assertEqual(allow_rec["decision"], "ALLOW")
        self.assertEqual(allow_rec["failed_rules"], [])

        # +1 second (1762961401) breaches both R4_7DAY_INQUIRY (604801s) and R5_CALL_WINDOW (21:00:01 IST)
        block_rec = evaluate_pre_dial(
            self.conn, "c_block", "+911600412900", self.r_ok, "INQUIRY_FOLLOWUP", 1762961401, 2, allow_rec["attestation_hash"]
        )
        self.assertEqual(block_rec["decision"], "BLOCK")
        self.assertIn("R4_7DAY_INQUIRY", block_rec["failed_rules"])
        self.assertIn("R5_CALL_WINDOW", block_rec["failed_rules"])

    def test_r3_blocks_when_dnd_robo_block_is_enabled(self) -> None:
        r_dnd = hmac_phone("+919876500001", "secret")
        self.conn.execute(
            "INSERT INTO consent_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("CNS-DND", r_dnd, 1, None, 1762356600, "artifact_sha256_ok", None),
        )
        rec = evaluate_pre_dial(
            self.conn, "c_dnd", "+911600412900", r_dnd, "INQUIRY_FOLLOWUP", 1762961400, 1, GENESIS_HASH
        )
        self.assertEqual(rec["decision"], "BLOCK")
        self.assertIn("R3_ROBO_DND_MODE", rec["failed_rules"])

    def test_r6_deduplicates_repeat_complainant_hmac(self) -> None:
        # Same complainant files 3 complaints in 10 days -> distinct count is 1 -> ALLOW
        for i in range(3):
            self.conn.execute(
                "INSERT INTO cdr_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"cdr_{i}", "+911600412900", self.r_ok, "INQUIRY_FOLLOWUP", 1762900000 + i, 45, 1, "same_voter_hmac", 0),
            )
        rec = evaluate_pre_dial(
            self.conn, "c_dedup", "+911600412900", self.r_ok, "INQUIRY_FOLLOWUP", 1762936200, 1, GENESIS_HASH
        )
        self.assertNotIn("R6_10DAY_CLUSTER", rec["failed_rules"])

        # Add a second distinct complainant + operator_ml_flag=1 -> triggers R6_10DAY_CLUSTER
        self.conn.execute(
            "INSERT INTO cdr_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("cdr_ml", "+911600412900", self.r_ok, "INQUIRY_FOLLOWUP", 1762900100, 30, 1, "second_voter_hmac", 1),
        )
        rec_blocked = evaluate_pre_dial(
            self.conn, "c_ml_block", "+911600412900", self.r_ok, "INQUIRY_FOLLOWUP", 1762936200, 2, rec["attestation_hash"]
        )
        self.assertIn("R6_10DAY_CLUSTER", rec_blocked["failed_rules"])
