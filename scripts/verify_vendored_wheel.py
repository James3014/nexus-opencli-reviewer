"""Fail closed unless the vendored wheel matches provenance.json wheel_sha256.

Usage: verify_vendored_wheel.py VENDOR_DIR
Prints the verified wheel's absolute path on stdout.
Exit 0 only when the wheel named by provenance exists and its sha256 matches.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

PROVENANCE = "repository-intelligence-engine.provenance.json"


def verify_wheel(vendor: Path) -> tuple[str, str]:
    """Return (sha256, wheel_filename) from ONE read of provenance."""
    provenance = json.loads((vendor / PROVENANCE).read_text(encoding="utf-8"))
    name = provenance.get("wheel_filename")
    expected = provenance.get("wheel_sha256")
    if not isinstance(name, str) or Path(name).name != name or not name.endswith(".whl"):
        raise ValueError("VENDOR_WHEEL_FILENAME_INVALID")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("VENDOR_WHEEL_SHA256_INVALID")
    actual = hashlib.sha256((vendor / name).read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, expected.lower()):
        raise ValueError(f"VENDOR_WHEEL_SHA256_MISMATCH expected={expected} actual={actual}")
    return actual, name


def verify(vendor: Path) -> str:
    return verify_wheel(vendor)[0]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_vendored_wheel.py VENDOR_DIR", file=sys.stderr)
        return 2
    try:
        vendor = Path(argv[1]).absolute()
        digest, name = verify_wheel(vendor)  # single provenance read: no re-read between check and use
        print(f"vendored wheel verified sha256={digest}", file=sys.stderr)
        print(vendor / name)  # stdout: only the verified wheel path; the action installs exactly this
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
