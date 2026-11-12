# LAW.md — Regulatory Mapping

Maps each deterministic pre-dial rule to the TRAI TCCCPR provision it enforces.

**Instrument:** Telecom Commercial Communications Customer Preference Regulations
(TCCCPR), Third Amendment, notified **18 September 2026** (TRAI Press Release
No. 119/2026).

This file records *which* rule implements *which* obligation. It is not legal
advice; it is a traceability table so a reviewer or auditor can walk from a
blocked call to the clause that required the block.

---

## Rule-to-clause traceability

| Rule | Obligation in plain terms | Clause family |
|------|---------------------------|---------------|
| `R1_CLI_DECLARED` | A commercial voice call may only originate from a calling line identity that is registered and active on the DLT platform. | Sender registration / DLT declaration |
| `R2_140_160_SERIES` | Promotional traffic must originate from the `140` series; service, transactional, and inquiry follow-up traffic from the `160` series (`1600` for BFSI). | Calling-line series allocation |
| `R3_ROBO_DND_MODE` | Calls to a subscriber who has registered a DND preference, or that are otherwise robocall-mode, must not be dialed. | Customer preference (DND) / unsolicited commercial communication |
| `R4_7DAY_INQUIRY` | An inquiry follow-up call is permitted only within 7 days of a verified customer inquiry, backed by a verifiable artifact. | Consent / inquiry evidence |
| `R5_CALL_WINDOW` | Commercial calls are permitted only between 09:00:00 and 21:00:00 IST. | Permissible calling hours |
| `R6_10DAY_CLUSTER` | A calling line that draws repeated complaints within 10 days is quarantined: 3+ unique complainants, or 2+ with an operator ML flag. | Complaint redressal / repeat-offender quarantine |

---

## Notes on interpretation

- **`R2` series prefixes.** `+91140` is the promotional series; `+91160` covers
  service, transactional, and inquiry follow-up. `+911600` is accepted as the
  BFSI sub-series under the `160` family.
- **`R4` "verified inquiry".** The regulation requires evidence, not assertion.
  The engine therefore requires *both* a non-null `inquiry_verified_ts` *and* a
  non-null `inquiry_artifact_sha256`. A timestamp without an artifact does not
  satisfy the rule.
- **`R5` window boundaries.** 09:00:00 and 21:00:00 are inclusive; 20:59:59 and
  21:00:01 are not. The window is evaluated in IST regardless of how the
  timestamp was encoded, so naive CDR strings are read as IST.
- **`R6` unique complainants.** The unit of count is the *unique complainant*,
  not the complaint row. A single subscriber filing many complaints is one
  complainant. The operator ML flag is an aggravating factor, not a standalone
  trigger: two unique complainants alone are insufficient unless ML also fired.
- **Quarantine, not deletion.** `R6` blocks dialing from the affected CLI; it does
  not erase declaration or consent history. The attestation ledger retains every
  blocked attempt.

---

## Evidence and audit

Every decision — allow or block — produces a hash-chained attestation record
(`SPEC.md` §4). The chain is tamper-evident: altering a stored decision or
skipping a sequence number is detectable. This supports the record-keeping
expectations that accompany the substantive obligations above.