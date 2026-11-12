import csv
import hashlib
import hmac
import sqlite3
from datetime import datetime, timedelta, timezone


IST = timezone(timedelta(seconds=19800))


def _normalize_e164(phone: str) -> str:
    cleaned = (
        phone.replace(" ", "")
        .replace("-", "")
        .replace("(", "")
        .replace(")", "")
        .strip()
    )
    if cleaned.startswith("+91"):
        return cleaned
    digits = "".join(ch for ch in cleaned if ch.isdigit())
    return "+91" + digits[-10:]


def hmac_phone(e164_phone: str, secret_key: str) -> str:
    e164 = _normalize_e164(e164_phone)
    return hmac.new(secret_key.encode(), e164.encode(), hashlib.sha256).hexdigest()


def parse_ist_timestamp(raw_ts: int | str) -> int:
    if isinstance(raw_ts, int):
        return raw_ts
    dt = datetime.strptime(raw_ts.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=IST)
    return int(dt.timestamp())


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE dlt_declarations (
            declaration_id TEXT PRIMARY KEY,
            cli_e164 TEXT,
            operator TEXT,
            series TEXT,
            status INTEGER,
            dlt_status TEXT,
            valid_from INTEGER,
            valid_to INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE consent_ledger (
            consent_id TEXT PRIMARY KEY,
            recipient_hmac TEXT,
            consent_flag INTEGER,
            withdrawal_ts INTEGER,
            inquiry_verified_ts INTEGER,
            inquiry_artifact_sha256 TEXT,
            revoked_ts INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE cdr_events (
            event_id TEXT PRIMARY KEY,
            cli_e164 TEXT,
            recipient_hmac TEXT,
            call_intent TEXT,
            call_ts INTEGER,
            duration_sec INTEGER,
            complaint_flag INTEGER,
            complainant_hmac TEXT,
            operator_ml_flag INTEGER
        )
        """
    )
    conn.execute("CREATE INDEX idx_cdr_cli_ts ON cdr_events(cli_e164, call_ts)")
    conn.execute("CREATE INDEX idx_consent_hmac ON consent_ledger(recipient_hmac)")
    conn.execute("CREATE INDEX idx_dlt_cli ON dlt_declarations(cli_e164)")


def _opt_int(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return None
    return int(value)


def _opt_text(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return None
    return value


def _hash_phone_or_none(value, secret_key):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return None
    return hmac_phone(value, secret_key)


def hydrate_csv_tables(
    conn: sqlite3.Connection,
    dlt_csv: str,
    consent_csv: str,
    cdr_csv: str,
    secret_key: str,
) -> dict[str, int]:
    counts: dict[str, int] = {}

    with open(dlt_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        conn.execute(
            "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["declaration_id"],
                _normalize_e164(row["cli_e164"]),
                row["operator"],
                row["series"],
                _opt_int(row["status"]),
                row["dlt_status"],
                _opt_int(row["valid_from"]),
                _opt_int(row["valid_to"]),
            ),
        )
    counts["dlt_declarations"] = len(rows)

    with open(consent_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        conn.execute(
            "INSERT INTO consent_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                row["consent_id"],
                hmac_phone(row["recipient_phone"], secret_key),
                _opt_int(row["consent_flag"]),
                _opt_int(row.get("withdrawal_ts")),
                _opt_int(row.get("inquiry_verified_ts")),
                _opt_text(row.get("inquiry_artifact_sha256")),
                _opt_int(row.get("revoked_ts")),
            ),
        )
    counts["consent_ledger"] = len(rows)

    with open(cdr_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        call_ts_raw = row["call_ts"].strip()
        if call_ts_raw.lstrip("-").isdigit():
            call_ts = int(call_ts_raw)
        else:
            call_ts = parse_ist_timestamp(call_ts_raw)
        conn.execute(
            "INSERT INTO cdr_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["event_id"],
                _normalize_e164(row["cli_e164"]),
                hmac_phone(row["recipient_phone"], secret_key),
                row["call_intent"],
                call_ts,
                _opt_int(row["duration_sec"]),
                _opt_int(row["complaint_flag"]),
                _hash_phone_or_none(row.get("complainant_phone"), secret_key),
                _opt_int(row["operator_ml_flag"]),
            ),
        )
    counts["cdr_events"] = len(rows)

    conn.commit()
    return counts
