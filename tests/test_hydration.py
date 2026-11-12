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
        self.assertEqual(tables, {"dlt_declarations", "consent_ledger", "cdr_events"})


if __name__ == "__main__":
    unittest.main()
