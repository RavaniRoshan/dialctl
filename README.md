# dialctl

> "Release early. Release often. Listen to your customers." — the dialctl
> limiting one-liner: **a pre-dial compliance gate that fails closed and never
> stops listening.** Every decision is logged, hash-chained, and auditable.

`dialctl` is a **local-first TRAI TCCCPR A2P voice compliance gate**. It
evaluates six deterministic pre-dial rules (R1–R6) against DLT declarations,
consent records, and CDR history before any outbound A2P call fires on Sarvam
AI, Exotel, or Ozonetel. Every decision appends a tamper-evident SHA-256
record to a hash-chained ledger, and a single-file browser app scans exported
CSVs for drift.

- **Zero runtime dependencies** — Python 3.12 standard library only.
- **< 5 ms p99** pre-dial budget (baseline ~0.044 ms p99).
- **Local-first** — no external network calls on the hot path; PII is
  HMAC-hashed before it touches disk.

---

## 60-second cold-run quickstart

```bash
git clone <this-repo> dialctl && cd dialctl
python3 hydrate_and_verify.py --self-test
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Or run the browser UI directly (no server required):

```bash
xdg-open web/index.html      # or: open web/index.html
```

`--self-test` verifies a 200-row smoke run **and** re-reads the exported
ledger to confirm the hash chain. No install step, no dependencies.

---

## Why Not: existing tools vs. dialctl

| Option | Why not (for this job) |
|--------|------------------------|
| **Exotel / Ozonetel / Sarvam native compliance** | The dialler vendors enforce their own platform rules, but you still need an independent, local pre-dial gate that works across all three and leaves an audit trail you control. Vendor dashboards are not an engineering artifact you can diff, hash, or replay offline. |
| **Excel / Google Sheets audit** | No enforcement (a sheet can't block a call), no tamper-evident ledger, and PII ends up in plaintext. |
| **A full rules engine (OPA/Drools)** | Overkill for six deterministic rules, and it breaks the zero-dependency, < 5 ms, offline-first constraints. |
| **A hosted compliance SaaS** | Sends subscriber data off-device and adds a network hop to the hot path. `dialctl` runs locally and hashes PII before storage. |

`dialctl` is the **independent, offline, hash-chained gate** you run in front
of whichever dialler you use.

---

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

---

## CLI

```bash
python3 hydrate_and_verify.py --self-test     # smoke + ledger chain verification
python3 hydrate_and_verify.py --smoke-test    # 200-row smoke run, prints precision
python3 hydrate_and_verify.py --benchmark     # iterations/sec + p99 latency
```

As a console script (after `pip install .`):

```bash
dialctl --self-test
```

---

## Benchmarks — how to reproduce

```bash
python3 hydrate_and_verify.py --benchmark
# iterations=10000 iterations_per_sec=... p99_ms=0.04...
```

**Methodology disclosure:** the benchmark evaluates `evaluate_pre_dial` in a
tight loop against an in-memory SQLite database seeded with one declaration,
one consent row, and a chained attestation hash. It measures the pure
evaluation path (no HTTP, no disk I/O). p99 is the 99th-percentile of per-call
wall-clock latency. Numbers vary by machine; the < 5 ms p99 budget is the
requirement, the reported figure is a local measurement.

---

## Legal & scope

- **Not legal advice or official TRAI/DLT certification.** `dialctl` is an
  engineering utility. It does not provide legal counsel and is not an
  official telecom-operator or TRAI/DLT certification. Verify obligations with
  qualified counsel and the relevant operator before relying on any output.
- **Privacy:** all processing is local. Uploaded CSVs stay in your browser's
  IndexedDB (`trai_a2p_audit_v1`); subscriber numbers are HMAC-hashed before
  storage. The **Clear stored data** button wipes all local audit data.
- **Termination exposure** figures ("Worst-Case Undeclared / Non-Exempt A2P
  Termination Exposure", ₹0.05 per ceiling minute, Tata Communications TRAI
  Filing) are upper-bound estimates for undeclared, non-exempt traffic — not a
  bill, quote, or guarantee.

See `SECURITY.md` for vulnerability reporting and `HMAC_SECRET_KEY` handling,
and `LICENSE` for the MIT terms.