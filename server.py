import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from hydrate_and_verify import (
    GENESIS_HASH,
    evaluate_pre_dial,
    hmac_phone,
    init_db,
    select_healthy_clis,
)


class ComplianceGateState:
    def __init__(self, conn, secret_key, seq_no=0, last_attestation_hash=GENESIS_HASH):
        self.conn = conn
        self.secret_key = secret_key
        self.seq_no = seq_no
        self.last_attestation_hash = last_attestation_hash
        self._lock = threading.Lock()

    @classmethod
    def create_with_sample_fixture(cls, secret_key):
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        init_db(conn)

        # DLT declaration making +911600412900 valid/ACTIVE for call_ts 1762936200
        conn.execute(
            "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "DLT-JIO-01",
                "+911600412900",
                "JIO",
                "160_SERVICE_BFSI",
                1,
                "ACTIVE",
                1758153600,
                1789689600,
            ),
        )

        # Consent for hmac_phone("+919876543210", secret_key) satisfying R4 at 1762936200
        recipient_hmac = hmac_phone("+919876543210", secret_key)
        conn.execute(
            "INSERT INTO consent_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "CNS-1",
                recipient_hmac,
                0,
                None,
                1762356600,  # inquiry age 579600s at 1762936200, within 7 days
                "artifact_sha256_ok",
                None,
            ),
        )

        # Healthy CLI row for /v1/cli/healthy consistency
        conn.execute(
            "INSERT INTO cli_registry VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("+911600412900", "ACTIVE", 1, 1, 0, 0, 0),
        )

        conn.commit()
        return cls(conn=conn, secret_key=secret_key)


REQUIRED_PAYLOAD_FIELDS = ("call_sid", "cli_e164", "customer_phone", "call_intent", "call_ts")
_STRING_PAYLOAD_FIELDS = ("call_sid", "cli_e164", "customer_phone", "call_intent")


def validate_payload(payload) -> str | None:
    """Return an error string when the payload is invalid, else None."""
    if not isinstance(payload, dict):
        return "non-object payload"
    missing = [k for k in REQUIRED_PAYLOAD_FIELDS if k not in payload]
    if missing:
        return f"missing required fields: {', '.join(missing)}"
    bad = [k for k in _STRING_PAYLOAD_FIELDS if not isinstance(payload[k], str)]
    if not isinstance(payload["call_ts"], int) or isinstance(payload["call_ts"], bool):
        bad.append("call_ts")
    if bad:
        return f"non-conforming required fields: {', '.join(bad)}"
    return None


def handle_pre_dial_payload(state, payload):
    error = validate_payload(payload)
    if error is not None:
        return (400, {"error": error})

    call_sid = payload["call_sid"]
    cli_e164 = payload["cli_e164"]
    customer_phone = payload["customer_phone"]
    call_intent = payload["call_intent"]
    call_ts = payload["call_ts"]

    recipient_hmac = hmac_phone(customer_phone, state.secret_key)

    with state._lock:
        state.seq_no += 1
        seq_no = state.seq_no
        prev_hash = state.last_attestation_hash
        record = evaluate_pre_dial(
            state.conn,
            call_sid,
            cli_e164,
            recipient_hmac,
            call_intent,
            call_ts,
            seq_no,
            prev_hash,
        )
        state.last_attestation_hash = record["attestation_hash"]

    status = 200 if record["decision"] == "ALLOW" else 403
    return (status, record)


class _ComplianceHandler(BaseHTTPRequestHandler):
    state = None

    def _send_json(self, status, obj):
        body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/v1/pre-dial/evaluate":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, {"error": "invalid JSON"})
                return
            status, record = handle_pre_dial_payload(self.state, payload)
            self._send_json(status, record)
            return
        self.send_error(404)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            index_path = Path(__file__).resolve().parent / "web" / "index.html"
            try:
                body = index_path.read_bytes()
            except OSError:
                self.send_error(500, "index.html unavailable")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/v1/cli/healthy":
            rows = select_healthy_clis(self.state.conn, None)
            self._send_json(200, rows)
            return
        self.send_error(404)

    def log_message(self, fmt, *args):
        return


def main(host="127.0.0.1", port=8080, state=None):
    if state is None:
        raise ValueError("state is required")
    _ComplianceHandler.state = state
    httpd = ThreadingHTTPServer((host, port), _ComplianceHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
