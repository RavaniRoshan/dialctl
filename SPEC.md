# SPEC.md — TRAI A2P Voice Compliance Rail

Normative requirements for the local-first pre-dial policy engine, the
attestation ledger, and the offline browser drift scanner.

Regulatory basis: TRAI TCCCPR Third Amendment, notified 18 September 2026
(TRAI Press Release No. 119/2026). See `LAW.md` for the clause mapping.

---

## 1. Scope and operating constraints

- **Local-first.** `evaluate_pre_dial()` performs no network I/O and makes no
  external calls. It runs against local SQLite only.
- **Latency budget.** `POST /v1/pre-dial/evaluate` and `evaluate_pre_dial()`
  complete in **< 5 ms p99** against an in-memory or WAL-backed database.
- **Dependency floor.** Python 3.12 standard library only on the hot path:
  `sqlite3`, `hashlib`, `hmac`, `csv`, `json`, `math`, `http.server`. No ORM, no
  OAuth, no third-party packages.
- **PII.** Numbers are normalized to E.164 and HMAC-hashed before any disk or
  browser persistence. Only 64-hex digests are stored.

---

## 2. Pre-dial rules (R1–R6)

Every rule is evaluated on every call. Rule names accumulate in `failed_rules`;
the decision is `ALLOW` only when `failed_rules` is empty.

### R1_CLI_DECLARED

The calling line identity (`cli_e164`) must have a matching row in
`dlt_declarations` whose `status = 1` (equivalently `dlt_status = 'ACTIVE'`), and
`valid_from <= call_ts <= valid_to`.

### R2_140_160_SERIES

The declared `series` must match the call intent:

| Intent | Required prefix |
|--------|-----------------|
| `PROMOTIONAL` | `+91140` |
| `SERVICE`, `TRANSACTIONAL`, `INQUIRY_FOLLOWUP` | `+91160` (accept `+911600` for BFSI) |

### R3_ROBO_DND_MODE

Block when the recipient has **no consent row**, when the consent row has
`dnd_robo_block = 1` (robo-call DND block enabled), or when `revoked_ts` is
non-null (consent revoked). A consent row with `dnd_robo_block = 0` and no
revocation does **not** trip this rule.

### R4_7DAY_INQUIRY

For `INQUIRY_FOLLOWUP`, require a consent row with a non-null
`inquiry_verified_ts` **and** a non-null `inquiry_artifact_sha256`, and:

```
0 <= (call_ts - inquiry_verified_ts) <= 604800
```

`604800` seconds = 7 days. Both bounds are inclusive.

### R5_CALL_WINDOW

Commercial calls are permitted strictly inside the window. Let
`ist_sec_of_day = (call_ts + 19800) % 86400`:

```
32400 <= ist_sec_of_day <= 75600
```

That is 09:00:00 through 21:00:00 IST inclusive.

### R6_10DAY_CLUSTER

Rolling 10-day window, `864000` seconds. For the CLI, over
`cdr_events` with `call_ts` in `[call_ts - 864000, call_ts]`:

- Let `distinct = COUNT(DISTINCT complainant_hmac)`
- Let `ml = COALESCE(SUM(operator_ml_flag), 0)`

Trip when `distinct >= 3`, **or** when `distinct >= 2` **and** `ml >= 1`.

`COUNT(DISTINCT ...)` is mandatory: three complaints from the same
`complainant_hmac` count as one unique complaint.

---

## 3. Exact boundary semantics (normative)

These are the load-bearing edges the test suite pins.

| Condition | Result |
|-----------|--------|
| `call_ts - inquiry_verified_ts == 604800` | **ALLOW** (inclusive) |
| `call_ts - inquiry_verified_ts == 604801` | **BLOCK** — `R4_7DAY_INQUIRY` |
| `ist_sec_of_day == 75600` (21:00:00 IST) | **ALLOW** (inclusive) |
| `ist_sec_of_day == 75601` (21:00:01 IST) | **BLOCK** — `R5_CALL_WINDOW` |
| `ist_sec_of_day == 32400` (09:00:00 IST) | **ALLOW** (inclusive) |
| `ist_sec_of_day == 32399` | **BLOCK** — `R5_CALL_WINDOW` |
| Three complaints, one `complainant_hmac`, `ml = 0` | **ALLOW** — 1 distinct |
| Two distinct complainants, `ml = 1` | **BLOCK** — `R6_10DAY_CLUSTER` |
| Naive `"2026-11-12 20:59:30"` | epoch `1762961370` (IST, not UTC) |

---

## 4. Attestation ledger

Every decision appends a record to a SHA-256 hash chain.

- `GENESIS_HASH = "0" * 64`.
- `compute_attestation_hash(prev_hash, payload)` copies `payload` without
  `attestation_hash`, serializes with
  `json.dumps(body, sort_keys=True, separators=(",", ":"))`, and returns
  `sha256(f"{prev_hash}|{canonical}").hexdigest()`.
- `verify_hash_chain(records)` returns `(True, "OK")` for a clean chain.
  Otherwise:
  - mutation of a stored field ⇒ `(False, "Payload tamper detected at seq_no=<n>")`
  - a `seq_no` gap ⇒ `(False, "Sequence gap at row <n>")`
- `export_attestations_jsonl(records, out_path)` writes one canonical JSON
  object per line.

---

## 5. Termination exposure and CLI risk score

### 5.1 Termination exposure

Billable A2P exposure is ₹0.05 per **ceiling minute**:

```python
compute_termination_exposure_inr(durations_sec) =
    round(sum(math.ceil(d / 60) * 0.05 for d in durations_sec if d > 0), 2)
```

| `duration_sec` | Billable minutes | Exposure |
|----------------|------------------|----------|
| `0` | 0 | ₹0.00 |
| `1` | 1 | ₹0.05 |
| `60` | 1 | ₹0.05 |
| `61` | 2 | ₹0.10 |

`duration_sec == 0` (unanswered ring) is never billable.

### 5.2 CLI risk score

```
complaint_term = 62.5 * (1.4 ** unique_complaints_10d - 1)
score = min(100.0, round(
    complaint_term
    + 15 * undeclared_calls
    + 10 * operator_ml_flags_10d
    +  5 * expired_inquiry_calls_10d
, 2))
```

The complaint term is pinned by the values below: with linear weights
`15/10/5`, the two non-zero pins force `a*(r**1 - 1) = 25` and
`a*(r**2 - 1) = 60`, giving `r = 1.4` and `a = 62.5`. The term is 0 at 0
complaints, 25 at 1, 60 at 2, and saturates via the outer `min(100.0, ...)`.

Pinned values:

| Inputs `(undeclared, complaints, ml_flags, expired)` | Score |
|------------------------------------------------------|-------|
| `(0, 0, 0, 0)` | `0.0` |
| `(0, 1, 0, 0)` | `25.0` |
| `(1, 2, 1, 3)` | `100.0` |

### 5.3 Healthy CLI routing filter

`select_healthy_clis(conn, now_ts)` derives health from `dlt_declarations` and
`cdr_events` (not `cli_registry`). A CLI is healthy when **all** hold:

- It has a declaration with `valid_from_ts <= now_ts AND valid_to_ts >= now_ts`
  and `status = 1` (or `dlt_status = 'ACTIVE'`).
- Over `cdr_events` with `call_ts BETWEEN (now_ts - 864000) AND now_ts`: at
  most 1 unique complainant (`COUNT(DISTINCT complainant_hmac) < 2`) and no
  operator ML flag (`COALESCE(SUM(operator_ml_flag), 0) = 0`).
- It has no undeclared calls in the same 10-day window.

`now_ts = None` defaults to `int(time.time())`. The returned dicts carry
`cli_e164`, `declaration_id`, `valid_from`, `valid_to`,
`unique_complaints_10d`, `operator_ml_flags_10d`, and
`undeclared_call_count_10d`.

---

## 6. HTTP webhook

| Method | Path | Success | Blocked |
|--------|------|---------|---------|
| POST | `/v1/pre-dial/evaluate` | `200` + decision record | `403` + decision record |
| GET | `/v1/cli/healthy` | `200` + healthy CLI list | — |

Payload keys: `call_sid`, `cli_e164`, `customer_phone`, `call_intent`,
`call_ts`. The handler hashes `customer_phone`, runs `evaluate_pre_dial`,
advances the chain, and returns the record.

Importing `server` must not bind a socket; the HTTP server starts only under
`main()`.

---

## 7. Smoke test gate

`run_smoke_test(limit, out_path)` evaluates `limit` synthetic fixtures through
`evaluate_pre_dial`, writes the chained ledger to `out_path`, and returns a
summary containing `rows_evaluated` and `rule_precision`. For `limit=200` it
must report `rows_evaluated == 200` and `rule_precision == 1.0`.

---

## 8. Browser UI invariants

`web/index.html` is a single self-contained file: inline CSS and ES2024 JS, no
external network requests, functional offline.

**Storage**

- IndexedDB database: `trai_a2p_audit_v1`
- localStorage key: `trai_a2p_ui_prefs_v1`

**Required tokens present in source**

`trai_a2p_audit_v1`, `trai_a2p_ui_prefs_v1`, `R1_CLI_DECLARED`,
`R2_140_160_SERIES`, `R3_ROBO_DND_MODE`, `R4_7DAY_INQUIRY`, `R5_CALL_WINDOW`,
`R6_10DAY_CLUSTER`, `0.05`, `604800`, `864000`, `crypto.subtle.digest`.

**Views**

1. CSV dropzone + Mahindra-scale synthetic sample loader.
2. Sortable CLI quarantine and drift table, with `0/3` complaint progress bars.
3. WebCrypto SHA-256 evidence-pack inspector drawer with JSONL export.

**Keyboard shortcuts**

| Key | Action |
|-----|--------|
| `j` | next row |
| `k` | previous row |
| `f` | flag / quarantine |
| `e` | open evidence drawer |
| `/` | focus search |

`scripts/verify_ui_invariants.py` exits `0` only when every token above is
present.