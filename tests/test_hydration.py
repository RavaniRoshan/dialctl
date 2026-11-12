import sqlite3
import unittest

from hydrate_and_verify import hmac_phone, parse_ist_timestamp, init_db


class TestHydration(unittest.TestCase):
    def test_hmac_phone_normalizes_10_digit_and_spaces(self):
        self.assertEqual(
            hmac_phone("98765 43210", "test-secret"),
            hmac_phone("+919876543210", "test-secret"),
        )
        self.assertEqual(len(hmac_phone("98765 43210", "test-secret")), 64)

    def test_parse_naive_ist_timestamp_and_epoch(self):
        # The plan's original literal was off by one year; this pins corrected values.
        self.assertEqual(parse_ist_timestamp("2026-11-12 20:59:30"), 1794497370)
        self.assertEqual(parse_ist_timestamp("2025-11-12 20:59:30"), 1762961370)
        self.assertEqual(parse_ist_timestamp(1762961370), 1762961370)

    def test_init_db_creates_wal_tables(self):
        conn = sqlite3.connect(":memory:")
        init_db(conn)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        self.assertEqual(
            tables,
            {"dlt_declarations", "consent_ledger", "cdr_events"},
        )


    def test_hydrate_csv_tables_scrubs_raw_phones_and_exports_jsonl(self) -> None:
        import json
        import tempfile
        from hydrate_and_verify import (
            GENESIS_HASH,
            compute_attestation_hash,
            export_attestations_jsonl,
            hydrate_csv_tables,
            verify_hash_chain,
        )

        conn = sqlite3.connect(":memory:")
        init_db(conn)
        with tempfile.TemporaryDirectory() as tmp:
            dlt_p = f"{tmp}/dlt.csv"
            cns_p = f"{tmp}/cns.csv"
            cdr_p = f"{tmp}/cdr.csv"
            out_p = f"{tmp}/attestations.jsonl"

            with open(dlt_p, "w", encoding="utf-8") as f:
                f.write("declaration_id,cli_e164,operator_name,series_type,a2p_voice_declared,status,valid_from_ts,valid_to_ts\n")
                f.write("DLT-1,+911600412900,JIO,160_SERVICE_BFSI,1,ACTIVE,1758153600,1789689600\n")
            with open(cns_p, "w", encoding="utf-8") as f:
                f.write("consent_id,recipient_phone,dnd_robo_block,explicit_consent_ts,inquiry_verified_ts,inquiry_artifact_sha256,revoked_ts\n")
                f.write("CNS-1,98765 43210,0,,1762800000,proof_hash,\n")
            with open(cdr_p, "w", encoding="utf-8") as f:
                f.write("call_sid,cli_e164,recipient_phone,call_intent,call_ts,duration_sec,ucc_complaint_filed,complainant_phone,operator_ml_flag\n")
                f.write("exo_1,+911600412900,+919876543210,INQUIRY_FOLLOWUP,1762936200,45,0,,0\n")

            counts = hydrate_csv_tables(conn, dlt_p, cns_p, cdr_p, secret_key="sec")
            self.assertEqual(counts, {"dlt": 1, "consent": 1, "cdr": 1})
            raw_leaks = conn.execute(
                "SELECT COUNT(*) FROM cdr_events WHERE recipient_hmac LIKE '%98765%'"
            ).fetchone()[0]
            self.assertEqual(raw_leaks, 0)

            rec = {
                "seq_no": 1,
                "call_sid": "exo_1",
                "evaluated_ts": 1762936200,
                "cli_e164": "+911600412900",
                "recipient_hmac": hmac_phone("+919876543210", "sec"),
                "decision": "ALLOW",
                "failed_rules": [],
                "inquiry_age_sec": 136200,
                "declaration_id": "DLT-1",
                "consent_id": "CNS-1",
                "prev_hash": GENESIS_HASH,
            }
            rec["attestation_hash"] = compute_attestation_hash(GENESIS_HASH, rec)
            export_attestations_jsonl([rec], out_p)
            with open(out_p, encoding="utf-8") as fh:
                loaded = [json.loads(line) for line in fh if line.strip()]
            ok, _ = verify_hash_chain(loaded)
            self.assertTrue(ok)


    def test_explicit_consent_ts_is_not_treated_as_revocation(self) -> None:
        import tempfile
        from hydrate_and_verify import (
            GENESIS_HASH,
            evaluate_pre_dial,
            hmac_phone,
            hydrate_csv_tables,
        )

        conn = sqlite3.connect(":memory:")
        init_db(conn)
        with tempfile.TemporaryDirectory() as tmp:
            dlt_p = f"{tmp}/dlt.csv"
            cns_p = f"{tmp}/cns.csv"
            cdr_p = f"{tmp}/cdr.csv"
            with open(dlt_p, "w", encoding="utf-8") as f:
                f.write("declaration_id,cli_e164,operator,series,status,dlt_status,valid_from,valid_to\n")
                f.write("DLT-1,+911600412900,JIO,160_SERVICE_BFSI,1,ACTIVE,1758153600,1789689600\n")
            with open(cns_p, "w", encoding="utf-8") as f:
                f.write("consent_id,recipient_phone,dnd_robo_block,explicit_consent_ts,inquiry_verified_ts,inquiry_artifact_sha256,revoked_ts\n")
                f.write("CNS-1,+919876543210,0,1762000000,1762800000,proof_hash,\n")
            with open(cdr_p, "w", encoding="utf-8") as f:
                f.write("event_id,cli_e164,recipient_phone,call_intent,call_ts,duration_sec,complaint_flag,complainant_phone,operator_ml_flag\n")
                f.write("cdr_1,+911600412900,+919876543210,INQUIRY_FOLLOWUP,1762936200,45,0,,0\n")

            hydrate_csv_tables(conn, dlt_p, cns_p, cdr_p, secret_key="sec")

            # explicit_consent_ts must not leak into withdrawal_ts or revoked_ts.
            cns_row = conn.execute(
                "SELECT withdrawal_ts, revoked_ts FROM consent_ledger WHERE consent_id = 'CNS-1'"
            ).fetchone()
            self.assertEqual(cns_row, (None, None))

            rec = evaluate_pre_dial(
                conn,
                "c_consent",
                "+911600412900",
                hmac_phone("+919876543210", "sec"),
                "INQUIRY_FOLLOWUP",
                1762936200,
                1,
                GENESIS_HASH,
            )
            self.assertEqual(rec["decision"], "ALLOW")
            self.assertNotIn("R3_ROBO_DND_MODE", rec["failed_rules"])


if __name__ == "__main__":
    unittest.main()


class TestCsvRowMapping(unittest.TestCase):
    """The mapping from a CSV row to a table row is pure and testable on its
    own — no files, no database. The alias policy lives in one place."""

    def test_map_consent_row_hashes_the_phone(self) -> None:
        from hydrate_and_verify import map_consent_row

        row = map_consent_row(
            {
                "consent_id": "CNS-1",
                "recipient_phone": "98765 43210",
                "dnd_robo_block": "0",
                "explicit_consent_ts": "1762000000",
                "inquiry_verified_ts": "1762800000",
                "inquiry_artifact_sha256": "proof",
                "revoked_ts": "",
            },
            secret_key="sec",
        )
        self.assertEqual(row[0], "CNS-1")
        self.assertEqual(len(row[1]), 64)  # hashed, not raw
        self.assertNotIn("98765", row[1])
        self.assertEqual(row[3], None)  # withdrawal_ts stays empty
        self.assertEqual(row[4], 1762800000)
        self.assertEqual(row[5], "proof")
        self.assertEqual(row[6], None)

    def test_map_dlt_row_accepts_both_header_spellings(self) -> None:
        from hydrate_and_verify import map_dlt_row

        new_style = map_dlt_row(
            {
                "declaration_id": "D1",
                "cli_e164": "+911600412900",
                "operator_name": "JIO",
                "series_type": "160_SERVICE_BFSI",
                "a2p_voice_declared": "1",
                "status": "ACTIVE",
                "valid_from_ts": "1758153600",
                "valid_to_ts": "1789689600",
            }
        )
        self.assertEqual(new_style[0], "D1")
        self.assertEqual(new_style[2], "JIO")
        self.assertEqual(new_style[3], "160_SERVICE_BFSI")
        self.assertEqual(new_style[4], 1)
        self.assertEqual(new_style[5], "ACTIVE")

        old_style = map_dlt_row(
            {
                "declaration_id": "D1",
                "cli_e164": "+911600412900",
                "operator": "JIO",
                "series": "160_SERVICE_BFSI",
                "status": 1,
                "dlt_status": "ACTIVE",
                "valid_from": 1758153600,
                "valid_to": 1789689600,
            }
        )
        self.assertEqual(old_style, new_style)

    def test_map_cdr_row_parses_naive_ist_and_hashes(self) -> None:
        from hydrate_and_verify import map_cdr_row

        row = map_cdr_row(
            {
                "call_sid": "exo_1",
                "cli_e164": "+911600412900",
                "recipient_phone": "+919876543210",
                "call_intent": "INQUIRY_FOLLOWUP",
                "call_ts": "2026-11-12 20:59:30",
                "duration_sec": "45",
                "ucc_complaint_filed": "0",
                "complainant_phone": "",
                "operator_ml_flag": "0",
            },
            secret_key="sec",
        )
        self.assertEqual(row[0], "exo_1")
        self.assertEqual(row[4], 1794497370)  # parsed as IST
        self.assertEqual(len(row[2]), 64)
        self.assertIsNone(row[7])  # no complainant -> NULL
