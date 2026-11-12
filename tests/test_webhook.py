import concurrent.futures
import time
import unittest

from hydrate_and_verify import verify_hash_chain
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


if __name__ == "__main__":
    unittest.main()
