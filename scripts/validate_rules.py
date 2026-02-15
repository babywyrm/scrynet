#!/usr/bin/env python3
"""Validate rules/*.json: parse JSON and compile regex patterns."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"


def main():
    ok = True
    for p in sorted(RULES_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError as e:
            print(f"FAIL {p.name}: {e}")
            ok = False
            continue
        for i, r in enumerate(data):
            name = r.get("name", f"<{i}>")
            try:
                re.compile(r["pattern"])
            except re.error as e:
                print(f"FAIL {p.name} [{name}]: {e}")
                ok = False
    if ok:
        print("✓ Rules valid")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
