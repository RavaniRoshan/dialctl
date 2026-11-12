# dialctl

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![Python](https://img.shields.io/badge/python-3.12%2B-blue?logo=python&logoColor=white)](https://www.python.org/) [![Docs](https://img.shields.io/badge/docs-online-blue)](https://dialctl-docs.antideploy.app) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](http://makeapullrequest.com)

[Documentation](https://dialctl-docs.antideploy.app) · [Rules reference](https://dialctl-docs.antideploy.app/reference/rules) · [Issues](https://github.com/RavaniRoshan/dialctl/issues) · [Security policy](SECURITY.md)

**A local-first TRAI TCCCPR A2P voice compliance gate that fails closed.**

`dialctl` decides whether an outbound A2P voice call may be dialed, before it is
dialed. It evaluates six deterministic pre-dial rules (R1–R6) against DLT
declarations, consent records, and CDR history before any call fires on Sarvam
AI, Exotel, or Ozonetel — and appends every decision, allow or block, to a
tamper-evident SHA-256 hash-chained ledger.

It runs on your machine. Subscriber numbers are HMAC-hashed before they touch
disk, the hot path makes no network calls, and the browser workbench keeps
everything in local IndexedDB.

## Install

No dependencies to install — the engine is Python 3.12 standard library only.

```sh
git clone https://github.com/RavaniRoshan/dialctl.git
cd dialctl
python3 hydrate_and_verify.py --self-test
```

Then verify it works:

```sh
python3 -m unittest discover -s tests -p "test_*.py" -v
```

## Quick Start

**Run the self-test** — a 200-row smoke evaluation, then re-read the exported
ledger and verify the hash chain:

```sh
python3 hydrate_and_verify.py --self-test
```

```txt
PASS: self-test smoke=200 precision=1.0 chain=OK
```

**Watch the rules decide a call** — this inquiry follow-up lands exactly on the
7-day boundary and inside the calling window, so it is allowed:

```python
import sqlite3
from hydrate_and_verify import init_db, hmac_phone, evaluate_pre_dial, GENESIS_HASH

conn = sqlite3.connect(":memory:")
init_db(conn)
conn.execute(
    "INSERT INTO dlt_declarations VALUES (?,?,?,?,?,?,?,?)",
    ("DLT-JIO-01", "+911600412900", "JIO", "160_SERVICE_BFSI",
     1, "ACTIVE", 1758153600, 1789689600),
)
recipient = hmac_phone("+919876543210", "demo-secret")
conn.execute(
    "INSERT INTO consent_ledger VALUES (?,?,?,?,?,?,?)",
    ("CNS-1", recipient, 0, None, 1762356600, "artifact_sha256_ok", None),
)

rec = evaluate_pre_dial(
    conn, "call_001", "+911600412900", recipient,
    "INQUIRY_FOLLOWUP", 1762961400, 1, GENESIS_HASH,
)
print(rec["decision"], rec["failed_rules"])   # ALLOW []
```

## Key Features

- **Deterministic pre-dial gate.** Six rules, evaluated on every call, each a
  pure comparison against stored data. No model, no score tuned by hand.
- **Under 5 ms p99.** The decision path reads local SQLite and returns —
  measured at ~0.05 ms p99 in the in-memory benchmark, far inside the budget.
- **Tamper-evident ledger.** Every decision is SHA-256 chained to the one before
  it. Flip a stored decision, or skip a sequence number, and `verify_hash_chain`
  reports it at the exact record.
- **PII hashed, never stored.** Numbers are normalized to E.164 and replaced
  with `HMAC-SHA256(secret_key, e164)` — 64 hex characters — before they reach
  SQLite, the JSONL ledger, or the browser.
- **Local-first.** No external network calls on the hot path. The decision is
  made from data you hydrated.
- **Offline browser workbench.** A single-file app parses exported DLT/consent/CDR
  CSVs, flags drift per CLI, and computes a WebCrypto SHA-256 digest for evidence
  packs — all in IndexedDB, with no network access.
- **Drop-in dialler wrapper.** `SarvamExotelComplianceMiddleware` raises before
  your dial callback runs, so a blocked call never reaches the carrier.

## Rules R1–R6

| Rule | Meaning |
|------|---------|
| `R1_CLI_DECLARED` | Calling line identity must be declared and active on DLT, within its validity window. |
| `R2_140_160_SERIES` | Promotional calls from `+91140`; service/transactional/inquiry from `+91160` (`+911600` BFSI). |
| `R3_ROBO_DND_MODE` | Block when the recipient has no consent row, has enabled the robo-call DND block, or has revoked consent. |
| `R4_7DAY_INQUIRY` | Inquiry follow-up only within 7 days (604800 s) of a verified inquiry backed by an artifact. |
| `R5_CALL_WINDOW` | Commercial calls only 09:00:00–21:00:00 IST. |
| `R6_10DAY_CLUSTER` | Quarantine a CLI at ≥ 3 unique complainants in 10 days, or ≥ 2 with an operator ML flag. |

Every rule is evaluated on every call; all failures accumulate in
`failed_rules`, and the call is `ALLOW` only when that list is empty.

The exact boundaries are normative and pinned by tests — 604800 s exactly is
allowed, 604801 is blocked; 21:00:00 IST is allowed, 21:00:01 is blocked. See
the [rules reference](https://dialctl-docs.antideploy.app/reference/rules).

## CLI

```sh
python3 hydrate_and_verify.py --self-test     # smoke + ledger chain verification
python3 hydrate_and_verify.py --smoke-test    # 200-row smoke run, prints precision
python3 hydrate_and_verify.py --benchmark     # iterations/sec + p99 latency
python3 hydrate_and_verify.py --smoke-test --limit 500   # custom row count
```

As a console script (after `pip install .`):

```sh
dialctl --self-test
```

## Run the pre-dial webhook

```python
from server import ComplianceGateState, main

state = ComplianceGateState.create_with_sample_fixture(secret_key="demo-secret")
main(host="127.0.0.1", port=8080, state=state)
```

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/pre-dial/evaluate` | Decide one call. `200` allow, `403` block, `400` malformed. |
| `GET` | `/v1/cli/healthy` | List CLIs that pass every health check at `?now_ts=`. |
| `GET` | `/` | Serve the browser workbench. |

```sh
curl -s -X POST http://127.0.0.1:8080/v1/pre-dial/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"call_sid":"c1","cli_e164":"+911600412900",
       "customer_phone":"+919876543210","call_intent":"INQUIRY_FOLLOWUP",
       "call_ts":1762936200}'
```

Full API and schema reference: [CLI and HTTP reference](https://dialctl-docs.antideploy.app/reference/cli-and-http).

## Benchmarks — how to reproduce

```sh
python3 hydrate_and_verify.py --benchmark
# iterations=10000 iterations_per_sec=52025.00 p99_ms=0.0494
```

(Figures vary by machine — the example above is one local run.)

**Methodology disclosure:** the benchmark evaluates `evaluate_pre_dial` in a
tight loop against an in-memory SQLite database seeded with one declaration,
one consent row, and a chained attestation hash. It measures the pure
evaluation path (no HTTP, no disk I/O). p99 is the 99th-percentile of per-call
wall-clock latency. Numbers vary by machine; the < 5 ms p99 budget is the
requirement, the reported figure is a local measurement. A warm HTTP decision
over loopback measures roughly 1–2 ms.

## Why Not: existing tools vs. dialctl

| Option | Why not (for this job) |
|--------|------------------------|
| **Exotel / Ozonetel / Sarvam native compliance** | The dialler vendors enforce their own platform rules, but you still need an independent, local pre-dial gate that works across all three and leaves an audit trail you control. Vendor dashboards are not an engineering artifact you can diff, hash, or replay offline. |
| **Excel / Google Sheets audit** | No enforcement (a sheet can't block a call), no tamper-evident ledger, and PII ends up in plaintext. |
| **A full rules engine (OPA/Drools)** | Overkill for six deterministic rules, and it breaks the zero-dependency, < 5 ms, offline-first constraints. |
| **A hosted compliance SaaS** | Sends subscriber data off-device and adds a network hop to the hot path. `dialctl` runs locally and hashes PII before storage. |

`dialctl` is the **independent, offline, hash-chained gate** you run in front of
whichever dialler you use.

## Docs

- [Your first blocked call](https://dialctl-docs.antideploy.app/tutorial/first-blocked-call) — tutorial
- [Run the pre-dial gate](https://dialctl-docs.antideploy.app/how-to/run-pre-dial-gate) — how-to
- [Verify the ledger](https://dialctl-docs.antideploy.app/how-to/verify-the-ledger) — how-to
- [CLI and HTTP reference](https://dialctl-docs.antideploy.app/reference/cli-and-http) — every flag, route, and field
- [The six rules](https://dialctl-docs.antideploy.app/reference/rules) — what each rule checks
- [Why a local gate](https://dialctl-docs.antideploy.app/explanation/why-a-local-gate) — design rationale
- [Scope and legal position](https://dialctl-docs.antideploy.app/explanation/scope)

## Develop

Requirements: Python 3.12+ (standard library only), Node.js 22.19+ for the docs site.

```sh
git clone https://github.com/RavaniRoshan/dialctl.git
cd dialctl
```

```sh
python3 -m unittest discover -s tests -p "test_*.py" -v   # run tests
python3 hydrate_and_verify.py --self-test                 # self-test + chain check
python3 scripts/verify_ui_invariants.py                   # browser UI invariants
```

The docs site lives in `docs-site/` (Blume, a static-first docs framework). See
its own README for build and deploy.

## Community

- [Issues](https://github.com/RavaniRoshan/dialctl/issues)
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Legal & scope

- **Not legal advice or official TRAI/DLT certification.** `dialctl` is an
  engineering utility. It does not provide legal counsel and is not an official
  telecom-operator or TRAI/DLT certification. Verify obligations with qualified
  counsel and the relevant operator before relying on any output.
- **Privacy:** all processing is local. Uploaded CSVs stay in your browser's
  IndexedDB (`trai_a2p_audit_v1`); subscriber numbers are HMAC-hashed before
  storage. The **Clear stored data** button wipes all local audit data.
- **Termination exposure** figures ("Worst-Case Undeclared / Non-Exempt A2P
  Termination Exposure", ₹0.05 per ceiling minute, Tata Communications TRAI
  Filing) are upper-bound estimates for undeclared, non-exempt traffic — not a
  bill, quote, or guarantee.

## License

Released under the [MIT License](LICENSE).