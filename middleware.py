from server import handle_pre_dial_payload


class ComplianceBlockError(Exception):
    def __init__(self, failed_rules, attestation_hash):
        self.failed_rules = failed_rules
        self.attestation_hash = attestation_hash
        super().__init__(f"Compliance blocked: {failed_rules}")


class SarvamExotelComplianceMiddleware:
    def __init__(self, state):
        self.state = state

    def dial(self, call_sid, cli_e164, customer_phone, call_intent, call_ts, dial_callback):
        payload = {
            "call_sid": call_sid,
            "cli_e164": cli_e164,
            "customer_phone": customer_phone,
            "call_intent": call_intent,
            "call_ts": call_ts,
        }
        _status, record = handle_pre_dial_payload(self.state, payload)
        if record["decision"] == "BLOCK":
            raise ComplianceBlockError(record["failed_rules"], record["attestation_hash"])
        return dial_callback()
