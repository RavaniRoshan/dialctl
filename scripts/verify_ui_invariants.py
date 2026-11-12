#!/usr/bin/env python3
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REQUIRED_TOKENS = [
    "trai_a2p_audit_v1",
    "trai_a2p_ui_prefs_v1",
    "R1_CLI_DECLARED",
    "R2_140_160_SERIES",
    "R3_ROBO_DND_MODE",
    "R4_7DAY_INQUIRY",
    "R5_CALL_WINDOW",
    "R6_10DAY_CLUSTER",
    "0.05",
    "604800",
    "864000",
    "crypto.subtle.digest",
    "sha256FallbackHex",
    "deleteDatabase",
    "ML-2/2",
    "100% Local Browser Execution",
    "Worst-Case Undeclared / Non-Exempt A2P Termination Exposure",
    "Not legal advice or official TRAI/DLT certification",
]

# FIPS 180-4 SHA-256 test vector: sha256("abc")
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def _extract_js_function(text: str, name: str) -> str:
    """Extract a top-level `function <name>(...) { ... }` by line-based brace counting."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().startswith(f"function {name}"):
            start = i
            break
    if start is None:
        return ""
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth == 0 and i > start:
            return "\n".join(lines[start : i + 1])
    return ""


def _run_sha256_vector(text: str) -> tuple[bool, str]:
    """Execute sha256FallbackHex('abc') under node and compare to the FIPS vector."""
    fn_body = _extract_js_function(text, "sha256FallbackHex")
    if not fn_body:
        return (False, "sha256FallbackHex not found in web/index.html")
    lines = text.splitlines()
    k_start = next(
        (i for i, l in enumerate(lines) if l.strip().startswith("const SHA256_K")),
        None,
    )
    k_stmt = ""
    if k_start is not None:
        k_end = next(i for i in range(k_start, len(lines)) if lines[i].strip().endswith("];"))
        k_stmt = "\n".join(lines[k_start : k_end + 1]) + "\n"
    script = (
        k_stmt
        + fn_body
        + "\nprocess.stdout.write(sha256FallbackHex('abc'));\n"
    )
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
        fh.write(script)
        script_path = fh.name
    try:
        proc = subprocess.run(
            ["node", script_path], capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        return (False, "node not available; cannot execute pure-JS SHA-256 vector")
    except subprocess.TimeoutExpired:
        return (False, "node timed out executing sha256FallbackHex")
    finally:
        Path(script_path).unlink(missing_ok=True)
    if proc.returncode != 0:
        return (False, f"node error: {proc.stderr.strip()}")
    got = proc.stdout.strip().lower()
    if got == SHA256_ABC:
        return (True, "sha256FallbackHex('abc') == FIPS 180-4 vector")
    return (False, f"sha256FallbackHex('abc') returned {got!r}, expected {SHA256_ABC!r}")


def main() -> int:
    html_path = Path(__file__).resolve().parent.parent / "web" / "index.html"
    if not html_path.exists():
        print("FAIL: web/index.html does not exist")
        return 1
    text = html_path.read_text(encoding="utf-8")
    missing = [token for token in REQUIRED_TOKENS if token not in text]
    if missing:
        for token in missing:
            print(f"FAIL: missing required token: {token}")
        return 1
    ok, detail = _run_sha256_vector(text)
    if not ok:
        print(f"FAIL: {detail}")
        return 1
    print(f"PASS: all {len(REQUIRED_TOKENS)} required UI invariant tokens present in web/index.html")
    print(f"PASS: {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
