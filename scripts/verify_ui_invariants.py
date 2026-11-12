#!/usr/bin/env python3
import sys
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
]


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
    print(f"PASS: all {len(REQUIRED_TOKENS)} required UI invariant tokens present in web/index.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
