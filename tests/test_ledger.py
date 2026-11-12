import copy
import unittest

from hydrate_and_verify import (
    GENESIS_HASH,
    compute_attestation_hash,
    verify_hash_chain,
)


class TestLedger(unittest.TestCase):
    def test_hash_chain_tamper_and_gap(self):
        r1 = {
            "seq_no": 1,
            "call_sid": "c1",
            "evaluated_ts": 1762961400,
            "cli_e164": "+911600412900",
            "recipient_hmac": "r1_hmac",
            "call_intent": "INQUIRY_FOLLOWUP",
            "decision": "ALLOW",
            "failed_rules": [],
            "inquiry_age_sec": 604800,
            "declaration_id": "DLT-JIO-01",
            "consent_id": "CNS-1",
            "prev_hash": GENESIS_HASH,
        }
        r1["attestation_hash"] = compute_attestation_hash(r1["prev_hash"], r1)

        r2 = {
            "seq_no": 2,
            "call_sid": "c2",
            "evaluated_ts": 1762961401,
            "cli_e164": "+911600412900",
            "recipient_hmac": "r1_hmac",
            "call_intent": "INQUIRY_FOLLOWUP",
            "decision": "BLOCK",
            "failed_rules": ["R4_7DAY_INQUIRY", "R5_CALL_WINDOW"],
            "inquiry_age_sec": 604801,
            "declaration_id": "DLT-JIO-01",
            "consent_id": "CNS-1",
            "prev_hash": r1["attestation_hash"],
        }
        r2["attestation_hash"] = compute_attestation_hash(r2["prev_hash"], r2)

        self.assertEqual(verify_hash_chain([r1, r2]), (True, "OK"))

        tampered = copy.deepcopy(r2)
        tampered["decision"] = "ALLOW"
        self.assertEqual(
            verify_hash_chain([r1, tampered]),
            (False, "Payload tamper detected at seq_no=2"),
        )

        gapped = copy.deepcopy(r2)
        gapped["seq_no"] = 3
        ok, msg = verify_hash_chain([r1, gapped])
        self.assertFalse(ok)
        self.assertIn("Sequence gap at row 2", msg)


if __name__ == "__main__":
    unittest.main()
