import time
import unittest

from middleware import ComplianceBlockError, SarvamExotelComplianceMiddleware
from server import ComplianceGateState, handle_pre_dial_payload


class TestWebhook(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
