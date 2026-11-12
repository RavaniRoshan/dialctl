import argparse
import csv
import hashlib
import hmac
import json
import math
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone


IST = timezone(timedelta(seconds=19800))

GENESIS_HASH = "0" * 64
SEVEN_DAYS_SEC = 604800
TEN_DAYS_SEC = 864000


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


def _pick(row, *names):
    """Return the first present value among candidate header names."""
    for name in names:
        if name in row:
            return row[name]
    return None


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
        declaration_id = _pick(row, "declaration_id")
        cli = _normalize_e164(_pick(row, "cli_e164"))
        operator = _pick(row, "operator", "operator_name")
        series = _pick(row, "series", "series_type")
        dlt_status = _pick(row, "dlt_status", "status")
        a2p_declared = _opt_int(_pick(row, "a2p_voice_declared"))
        if a2p_declared is None:
            a2p_declared = _opt_int(_pick(row, "status"))
        conn.execute(
            "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                declaration_id,
                cli,
                operator,
                series,
                a2p_declared,
                dlt_status,
                _opt_int(_pick(row, "valid_from", "valid_from_ts")),
                _opt_int(_pick(row, "valid_to", "valid_to_ts")),
            ),
        )
    counts["dlt"] = len(rows)

    with open(consent_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        recipient_hmac = _hash_phone_or_none(
            _pick(row, "recipient_phone", "recipient_hmac"), secret_key
        )
        conn.execute(
            "INSERT INTO consent_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                _pick(row, "consent_id"),
                recipient_hmac,
                _opt_int(_pick(row, "dnd_robo_block", "consent_flag")),
                # explicit_consent_ts is when consent was GIVEN, not withdrawn;
                # it must never populate withdrawal_ts or revoked_ts.
                _opt_int(row.get("withdrawal_ts")),
                _opt_int(row.get("inquiry_verified_ts")),
                _opt_text(row.get("inquiry_artifact_sha256")),
                _opt_int(row.get("revoked_ts")),
            ),
        )
    counts["consent"] = len(rows)

    with open(cdr_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        call_ts_raw = _pick(row, "call_ts").strip()
        if call_ts_raw.lstrip("-").isdigit():
            call_ts = int(call_ts_raw)
        else:
            call_ts = parse_ist_timestamp(call_ts_raw)
        conn.execute(
            "INSERT INTO cdr_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _pick(row, "event_id", "call_sid"),
                _normalize_e164(_pick(row, "cli_e164")),
                _hash_phone_or_none(_pick(row, "recipient_phone", "recipient_hmac"), secret_key),
                _pick(row, "call_intent"),
                call_ts,
                _opt_int(row.get("duration_sec")),
                _opt_int(_pick(row, "complaint_flag", "ucc_complaint_filed")),
                _hash_phone_or_none(row.get("complainant_phone"), secret_key),
                _opt_int(row.get("operator_ml_flag")),
            ),
        )
    counts["cdr"] = len(rows)

    conn.commit()
    return counts


def compute_attestation_hash(prev_hash: str, payload: dict) -> str:
    body = {k: v for k, v in payload.items() if k != "attestation_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode()).hexdigest()


def evaluate_pre_dial(
    conn: sqlite3.Connection,
    call_sid: str,
    cli_e164: str,
    recipient_hmac: str,
    call_intent: str,
    call_ts: int,
    seq_no: int,
    prev_hash: str,
) -> dict:
    failed_rules: list[str] = []
    declaration_id = None
    consent_id = None
    inquiry_age_sec = None

    # R1_CLI_DECLARED
    decl_rows = conn.execute(
        """
        SELECT declaration_id, series, status, dlt_status, valid_from, valid_to
        FROM dlt_declarations
        WHERE cli_e164 = ?
        """,
        (cli_e164,),
    ).fetchall()
    matched_decl = None
    for row in decl_rows:
        did, _series, status, dlt_status, valid_from, valid_to = row
        active = (status == 1) or (dlt_status == "ACTIVE")
        if active and valid_from <= call_ts <= valid_to:
            matched_decl = row
            break
    if matched_decl is None:
        failed_rules.append("R1_CLI_DECLARED")
    else:
        declaration_id = matched_decl[0]

    # R2_140_160_SERIES
    if call_intent == "PROMOTIONAL":
        if not cli_e164.startswith("+91140"):
            failed_rules.append("R2_140_160_SERIES")
    elif call_intent in ("SERVICE", "TRANSACTIONAL", "INQUIRY_FOLLOWUP"):
        if not cli_e164.startswith("+91160"):
            failed_rules.append("R2_140_160_SERIES")
    else:
        failed_rules.append("R2_140_160_SERIES")

    # Consent rows for recipient
    consent_rows = conn.execute(
        """
        SELECT consent_id, consent_flag, withdrawal_ts, inquiry_verified_ts,
               inquiry_artifact_sha256, revoked_ts
        FROM consent_ledger
        WHERE recipient_hmac = ?
        """,
        (recipient_hmac,),
    ).fetchall()

    # R3_ROBO_DND_MODE: block when consent is absent, the recipient enabled the
    # robo-call DND block, or consent was revoked.
    # consent_row = (consent_id, dnd_robo_block, withdrawal_ts, inquiry_verified_ts,
    #                inquiry_artifact_sha256, revoked_ts)
    consent_row = consent_rows[0] if consent_rows else None
    if not consent_row or consent_row[1] == 1 or consent_row[5] is not None:
        failed_rules.append("R3_ROBO_DND_MODE")

    # R4_7DAY_INQUIRY and consent/inquiry fields
    if call_intent == "INQUIRY_FOLLOWUP":
        r4_ok = False
        best_consent = None
        # Prefer a consent row that satisfies R4
        for c in consent_rows:
            cid, _cf, _wts, ivt, artifact, _rts = c
            if ivt is not None and artifact is not None:
                age = int(call_ts - ivt)
                if 0 <= age <= SEVEN_DAYS_SEC:
                    r4_ok = True
                    best_consent = c
                    inquiry_age_sec = age
                    consent_id = cid
                    break
        if not r4_ok:
            failed_rules.append("R4_7DAY_INQUIRY")
            # Best-effort reporting: pick a consent with inquiry data/age if present
            for c in consent_rows:
                cid, _cf, _wts, ivt, artifact, _rts = c
                if ivt is not None and artifact is not None:
                    inquiry_age_sec = int(call_ts - ivt)
                    consent_id = cid
                    best_consent = c
                    break
            if best_consent is None:
                for c in consent_rows:
                    cid, _cf, _wts, ivt, _artifact, _rts = c
                    if ivt is not None:
                        inquiry_age_sec = int(call_ts - ivt)
                        consent_id = cid
                        best_consent = c
                        break
            if best_consent is None and consent_rows:
                consent_id = consent_rows[0][0]
    else:
        if consent_rows:
            consent_id = consent_rows[0][0]

    # R5_CALL_WINDOW
    ist_sec_of_day = (call_ts + 19800) % 86400
    if not (32400 <= ist_sec_of_day <= 75600):
        failed_rules.append("R5_CALL_WINDOW")

    # R6_10DAY_CLUSTER
    window_start = call_ts - TEN_DAYS_SEC
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT complainant_hmac), COALESCE(SUM(operator_ml_flag), 0)
        FROM cdr_events
        WHERE cli_e164 = ?
          AND call_ts >= ?
          AND call_ts <= ?
          AND complaint_flag = 1
        """,
        (cli_e164, window_start, call_ts),
    ).fetchone()
    distinct = row[0] if row else 0
    ml = row[1] if row else 0
    if distinct >= 3 or (distinct >= 2 and ml >= 1):
        failed_rules.append("R6_10DAY_CLUSTER")

    decision = "ALLOW" if not failed_rules else "BLOCK"
    record = {
        "seq_no": seq_no,
        "call_sid": call_sid,
        "evaluated_ts": call_ts,
        "cli_e164": cli_e164,
        "recipient_hmac": recipient_hmac,
        "call_intent": call_intent,
        "decision": decision,
        "failed_rules": failed_rules,
        "inquiry_age_sec": inquiry_age_sec,
        "declaration_id": declaration_id,
        "consent_id": consent_id,
        "prev_hash": prev_hash,
    }
    record["attestation_hash"] = compute_attestation_hash(prev_hash, record)
    return record


def verify_hash_chain(records: list[dict]) -> tuple[bool, str]:
    expected_prev = GENESIS_HASH
    for i, row in enumerate(records):
        if row["seq_no"] != i + 1:
            return (False, f"Sequence gap at row {i + 1}")
        if row["prev_hash"] != expected_prev:
            return (False, f"Previous-hash mismatch at row {i + 1}")
        recomputed = compute_attestation_hash(row["prev_hash"], row)
        if recomputed != row["attestation_hash"]:
            return (False, f"Payload tamper detected at seq_no={row['seq_no']}")
        expected_prev = row["attestation_hash"]
    return (True, "OK")


def export_attestations_jsonl(records: list[dict], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def compute_cli_risk_score(
    undeclared_calls,
    unique_complaints_10d,
    operator_ml_flags_10d,
    expired_inquiry_calls_10d,
) -> float:
    complaint_term = 62.5 * (1.4 ** unique_complaints_10d - 1)
    total = (
        complaint_term
        + 15 * undeclared_calls
        + 10 * operator_ml_flags_10d
        + 5 * expired_inquiry_calls_10d
    )
    return min(100.0, round(total, 2))


def compute_termination_exposure_inr(durations_sec) -> float:
    return round(sum(math.ceil(d / 60) * 0.05 for d in durations_sec if d > 0), 2)


def select_healthy_clis(conn: sqlite3.Connection, now_ts) -> list[dict]:
    if now_ts is None:
        now_ts = int(time.time())

    decl_rows = conn.execute(
        """
        SELECT cli_e164, declaration_id, status, dlt_status, valid_from, valid_to
        FROM dlt_declarations
        WHERE valid_from <= ? AND valid_to >= ?
        """,
        (now_ts, now_ts),
    ).fetchall()

    healthy: list[dict] = []
    for cli_e164, declaration_id, status, dlt_status, valid_from, valid_to in decl_rows:
        active = (status == 1) or (dlt_status == "ACTIVE")
        if not active:
            continue

        complaint_row = conn.execute(
            """
            SELECT COUNT(DISTINCT complainant_hmac), COALESCE(SUM(operator_ml_flag), 0)
            FROM cdr_events
            WHERE cli_e164 = ?
              AND complaint_flag = 1
              AND call_ts BETWEEN ? AND ?
            """,
            (cli_e164, now_ts - TEN_DAYS_SEC, now_ts),
        ).fetchone()
        unique_complaints = complaint_row[0] if complaint_row else 0
        ml_flags = complaint_row[1] if complaint_row else 0

        if unique_complaints >= 2 or ml_flags >= 1:
            continue

        undeclared = conn.execute(
            """
            SELECT COUNT(*)
            FROM cdr_events
            WHERE cli_e164 = ?
              AND call_ts BETWEEN ? AND ?
              AND complaint_flag = 0
              AND call_intent IN ('PROMOTIONAL', 'SERVICE', 'TRANSACTIONAL', 'INQUIRY_FOLLOWUP')
              AND NOT EXISTS (
                  SELECT 1 FROM dlt_declarations d
                  WHERE d.cli_e164 = cdr_events.cli_e164
                    AND (d.status = 1 OR d.dlt_status = 'ACTIVE')
                    AND d.valid_from <= cdr_events.call_ts
                    AND d.valid_to >= cdr_events.call_ts
              )
            """,
            (cli_e164, now_ts - TEN_DAYS_SEC, now_ts),
        ).fetchone()[0]

        if undeclared > 0:
            continue

        healthy.append(
            {
                "cli_e164": cli_e164,
                "declaration_id": declaration_id,
                "valid_from": valid_from,
                "valid_to": valid_to,
                "unique_complaints_10d": unique_complaints,
                "operator_ml_flags_10d": ml_flags,
                "undeclared_call_count_10d": undeclared,
            }
        )

    return healthy


def run_smoke_test(limit, out_path) -> dict:
    conn = sqlite3.connect(":memory:")
    init_db(conn)

    cli_e164 = "+911600412900"
    conn.execute(
        "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "DLT-SMOKE-01",
            cli_e164,
            "JIO",
            "160_SERVICE_BFSI",
            1,
            "ACTIVE",
            1758153600,
            1789689600,
        ),
    )

    recipient_hmac = hmac_phone("+919876543210", "smoke-secret")
    inquiry_verified_ts = 1762356600
    conn.execute(
        "INSERT INTO consent_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "CNS-SMOKE-1",
            recipient_hmac,
            0,
            None,
            inquiry_verified_ts,
            "artifact_sha256_smoke",
            None,
        ),
    )

    call_ts = 1762936200  # 2026-11-12 14:00:00 IST, inquiry age 579600s
    records = []
    prev_hash = GENESIS_HASH
    correct = 0
    for i in range(limit):
        seq_no = i + 1
        call_sid = f"smoke_{i}"
        record = evaluate_pre_dial(
            conn,
            call_sid,
            cli_e164,
            recipient_hmac,
            "INQUIRY_FOLLOWUP",
            call_ts,
            seq_no,
            prev_hash,
        )
        expected_decision = "ALLOW"
        if record["decision"] == expected_decision and record["failed_rules"] == []:
            correct += 1
        records.append(record)
        prev_hash = record["attestation_hash"]

    export_attestations_jsonl(records, out_path)

    total = limit
    precision = (correct / total) if total else 0.0
    assert precision == 1.0
    return {"rows_evaluated": limit, "rule_precision": precision}


def _benchmark_evaluate_pre_dial(iterations: int = 10000) -> dict:
    conn = sqlite3.connect(":memory:")
    init_db(conn)

    cli_e164 = "+911600412900"
    conn.execute(
        "INSERT INTO dlt_declarations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "DLT-BENCH-01",
            cli_e164,
            "JIO",
            "160_SERVICE_BFSI",
            1,
            "ACTIVE",
            1758153600,
            1789689600,
        ),
    )

    secret = "bench-secret"
    recipient_hmac = hmac_phone("+919876543210", secret)
    conn.execute(
        "INSERT INTO consent_ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "CNS-BENCH-1",
            recipient_hmac,
            0,
            None,
            1762356600,
            "artifact_sha256_bench",
            None,
        ),
    )

    call_ts = 1762936200
    prev_hash = GENESIS_HASH
    durations = []
    start = time.perf_counter()
    for i in range(iterations):
        t0 = time.perf_counter()
        rec = evaluate_pre_dial(
            conn,
            f"bench_{i}",
            cli_e164,
            recipient_hmac,
            "INQUIRY_FOLLOWUP",
            call_ts,
            i + 1,
            prev_hash,
        )
        durations.append((time.perf_counter() - t0) * 1000.0)
        prev_hash = rec["attestation_hash"]
    total = time.perf_counter() - start
    durations_sorted = sorted(durations)
    idx = int(math.ceil(0.99 * len(durations_sorted))) - 1
    if idx < 0:
        idx = 0
    p99_ms = durations_sorted[idx]
    iters_per_sec = iterations / total if total > 0 else 0.0
    return {
        "iterations": iterations,
        "iterations_per_sec": iters_per_sec,
        "p99_ms": p99_ms,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="TRAI A2P compliance rail CLI")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true", dest="self_test")
    group.add_argument("--smoke-test", action="store_true", dest="smoke_test")
    group.add_argument("--benchmark", action="store_true", dest="benchmark")
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        dest="limit",
        help="row count for --smoke-test (default: 200)",
    )
    args = parser.parse_args(argv)

    if args.smoke_test:
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "smoke.jsonl")
            summary = run_smoke_test(limit=args.limit, out_path=out_path)
        print(json.dumps(summary, sort_keys=True))
        return 0

    if args.self_test:
        try:
            with tempfile.TemporaryDirectory() as td:
                out_path = os.path.join(td, "self_test.jsonl")
                summary = run_smoke_test(limit=200, out_path=out_path)
                ok_summary = (
                    summary.get("rows_evaluated") == 200
                    and summary.get("rule_precision") == 1.0
                )
                records = []
                with open(out_path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            records.append(json.loads(line))
                chain_ok, chain_msg = verify_hash_chain(records)
                ok = ok_summary and chain_ok
                if ok:
                    print("PASS: self-test smoke=200 precision=1.0 chain=OK")
                    return 0
                print(
                    f"FAIL: smoke_ok={ok_summary} chain_ok={chain_ok} chain_msg={chain_msg} summary={summary}"
                )
                return 1
        except Exception as exc:
            print(f"FAIL: {exc}")
            return 1

    if args.benchmark:
        result = _benchmark_evaluate_pre_dial(iterations=10000)
        print(
            f"iterations={result['iterations']} "
            f"iterations_per_sec={result['iterations_per_sec']:.2f} "
            f"p99_ms={result['p99_ms']:.4f}"
        )
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

