# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue or pull request.

- Email: <security@dialctl.invalid>
- Or use GitHub's private vulnerability reporting on the repository's
  **Security** tab ("Report a vulnerability").

Include a description, affected version, reproduction steps, and impact. We
aim to acknowledge within 72 hours and to ship a fix or mitigation plan within
14 days for confirmed High/Critical issues.

## Handling `HMAC_SECRET_KEY`

`dialctl` never stores raw subscriber phone numbers. Every number is
normalized to E.164 (`+91XXXXXXXXXX`) and hashed with
`HMAC-SHA256(HMAC_SECRET_KEY, e164_phone)`, producing a 64-character lowercase
hex digest before it reaches SQLite, the JSONL ledger, or the browser.

Because the digest is only as strong as the key:

- **Never commit `HMAC_SECRET_KEY`** or any real key to source control, CI
  logs, or issue trackers. Load it from an environment variable or a secrets
  manager.
- Use a high-entropy key (≥ 32 bytes). A weak key makes the digests
  brute-forceable, which would re-identify subscribers.
- **Rotating the key re-identifies nothing but invalidates existing digests**:
  previously stored hashes will no longer match, so plan re-hydration if you
  rotate.
- Treat the key, the SQLite database, and exported `attestations.jsonl` files
  as sensitive: the digests plus call metadata can still be correlated.

## PII and data handling

- Raw phone numbers are hashed on ingest and are never persisted in plaintext.
- Exported evidence packs contain hashed identifiers and call metadata only.
- The browser UI stores parsed records in local IndexedDB
  (`trai_a2p_audit_v1`); nothing is transmitted to a server. Use **Clear
  stored data** to wipe it.

## Scope

dialctl is an **engineering utility**, not legal counsel and not an official
telecom-operator or TRAI/DLT certification. It supports compliance workflows;
it does not certify compliance. See `README.md` for the full disclaimer.