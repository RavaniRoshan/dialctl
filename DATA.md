# DATA.md — TRAI A2P Voice Compliance Rail Data Contracts

This document is normative for schemas. Column **order** is load-bearing: every
test in `tests/` uses positional `INSERT INTO <table> VALUES (?, ?, ...)` with no
column list, so the order below must be preserved exactly.

All timestamps are integer Unix epoch **seconds** in UTC. Phone numbers supplied
to `hmac_phone()` are normalized to E.164 `+91XXXXXXXXXX` before hashing.

---

## 1. PII normalization and hashing

| Field | Rule |
|-------|------|
| Input forms accepted | `"+919876543210"`, `"9876543210"`, `"98765 43210"`, `"98765-43210"` |
| Normalized form | `+91` followed by exactly 10 digits |
| Hash | `HMAC-SHA256(HMAC_SECRET_KEY, e164_phone)`, 64 lowercase hex chars |
| API | `hmac_phone(e164_phone: str, secret_key: str) -> str` |

No raw phone number is persisted to SQLite, JSONL, or the browser. Only the
64-hex-char digest is stored under `*_hmac` column names.

---

## 2. Timestamp parsing

| Input | Interpretation | Epoch |
|-------|----------------|-------|
| `1762961370` (int) | already epoch | `1762961370` |
| `"2026-11-12 20:59:30"` (naive str) | **IST (UTC+05:30)** | `1762961370` |
| `"2026-11-12T15:29:30+00:00"` (aware str) | as written | `1762961370` |

Naive strings from Exotel/Ozonetel CDR exports are treated as IST, not UTC.
Reading them as UTC would shift evening calls four and a half hours earlier and
wrongly trip `R5_CALL_WINDOW`.

---

## 3. SQLite schema

Engine: SQLite in **WAL mode** (`PRAGMA journal_mode=WAL`), opened through the
Python 3.12 standard-library `sqlite3` module.

### 3.1 `dlt_declarations` — 8 columns

| # | Column | Type | Notes |
|---|--------|------|-------|
| 1 | `declaration_id` | TEXT | PRIMARY KEY, e.g. `DLT-JIO-01` |
| 2 | `cli_e164` | TEXT | declared calling line identity, E.164 |
| 3 | `operator` | TEXT | e.g. `JIO` |
| 4 | `series` | TEXT | e.g. `160_SERVICE_BFSI`, `140_PROMO` |
| 5 | `status` | INTEGER | `1` = declared/active, `0` = not |
| 6 | `dlt_status` | TEXT | `ACTIVE` \| `SUSPENDED` \| `EXPIRED` |
| 7 | `valid_from` | INTEGER | epoch seconds, inclusive |
| 8 | `valid_to` | INTEGER | epoch seconds, inclusive |

### 3.2 `consent_ledger` — 7 columns

| # | Column | Type | Notes |
|---|--------|------|-------|
| 1 | `consent_id` | TEXT | PRIMARY KEY, e.g. `CNS-1` |
| 2 | `recipient_hmac` | TEXT | HMAC-SHA256 of recipient E.164 |
| 3 | `consent_flag` | INTEGER | `1` = consent recorded, `0` = none |
| 4 | `withdrawal_ts` | INTEGER | epoch seconds or NULL |
| 5 | `inquiry_verified_ts` | INTEGER | epoch seconds or NULL |
| 6 | `inquiry_artifact_sha256` | TEXT | 64-hex digest of evidence, or NULL |
| 7 | `revoked_ts` | INTEGER | epoch seconds or NULL |

### 3.3 `cdr_events` — 9 columns

| # | Column | Type | Notes |
|---|--------|------|-------|
| 1 | `event_id` | TEXT | PRIMARY KEY, e.g. `cdr_0` |
| 2 | `cli_e164` | TEXT | calling line identity, E.164 |
| 3 | `recipient_hmac` | TEXT | HMAC-SHA256 of called number |
| 4 | `call_intent` | TEXT | `INQUIRY_FOLLOWUP` \| `PROMOTIONAL` \| `SERVICE` \| `TRANSACTIONAL` |
| 5 | `call_ts` | INTEGER | epoch seconds |
| 6 | `duration_sec` | INTEGER | `0` for unanswered rings |
| 7 | `complaint_flag` | INTEGER | `1` when the row is a complaint |
| 8 | `complainant_hmac` | TEXT | HMAC of complainant; NULL when not a complaint |
| 9 | `operator_ml_flag` | INTEGER | `1` when operator ML raised a flag |

### 3.4 Indexes

| Index | Columns |
|-------|---------|
| `idx_cdr_cli_ts` | `cdr_events(cli_e164, call_ts)` |
| `idx_consent_hmac` | `consent_ledger(recipient_hmac)` |
| `idx_dlt_cli` | `dlt_declarations(cli_e164)` |

---

## 4. CSV input layouts

Hydration uses `csv.DictReader`, so header names must match the table columns.
Every phone-like column is passed through `hmac_phone()` before insert.

### 4.1 DLT CSV

```csv
declaration_id,cli_e164,operator,series,status,dlt_status,valid_from,valid_to
DLT-JIO-01,+911600412900,JIO,160_SERVICE_BFSI,1,ACTIVE,1758153600,1789689600
```

### 4.2 Consent CSV

```csv
consent_id,recipient_phone,consent_flag,withdrawal_ts,inquiry_verified_ts,inquiry_artifact_sha256,revoked_ts
CNS-1,+919876543210,1,,1762356600,artifact_sha256_ok,
```

`recipient_phone` is hashed into `recipient_hmac`.

### 4.3 CDR CSV

```csv
event_id,cli_e164,recipient_phone,call_intent,call_ts,duration_sec,complaint_flag,complainant_phone,operator_ml_flag
cdr_0,+911600412900,+919876543210,INQUIRY_FOLLOWUP,2026-11-12 14:00:00,45,0,,0
```

Naive `call_ts` strings are parsed as IST. `complainant_phone` is hashed into
`complainant_hmac` (NULL/empty stays NULL).

---

## 5. Attestation ledger JSONL

One JSON object per line. Keys are serialized with
`json.dumps(record, sort_keys=True, separators=(",", ":"))`.

| Key | Type | Notes |
|-----|------|-------|
| `seq_no` | int | 1-based, gapless |
| `call_sid` | str | caller-supplied call identifier |
| `evaluated_ts` | int | epoch seconds |
| `cli_e164` | str | calling line identity |
| `recipient_hmac` | str | 64-hex digest |
| `decision` | str | `ALLOW` \| `BLOCK` |
| `failed_rules` | list[str] | empty when ALLOW |
| `inquiry_age_sec` | int \| null | seconds since verified inquiry |
| `declaration_id` | str \| null | matched DLT declaration |
| `consent_id` | str \| null | matched consent row |
| `prev_hash` | str | 64-hex, `GENESIS_HASH` for the first row |
| `attestation_hash` | str | 64-hex SHA-256 over `prev_hash` + canonical body |

`compute_attestation_hash(prev_hash, payload)` excludes `attestation_hash`
itself, serializes the remainder canonically, and hashes
`f"{prev_hash}|{canonical}"` with SHA-256.