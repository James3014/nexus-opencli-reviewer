"""Repository Intelligence CLI.

Deterministic, pure local JSON adapter for Repository Intelligence Core V1 operations.
No GitHub/network/state writes.
Claim ceiling: PR_INTELLIGENCE_ONLY.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from reviewer.intelligence import (
    CLAIM_CEILING,
    CI_EVIDENCE_CLAIM_CEILING,
    analyze_change_impact,
    analyze_cross_pr_overlap,
    classify_readiness,
    fingerprint_ci_failures,
    revision_identity,
)

OPERATIONS: frozenset[str] = frozenset({
    "revision",
    "readiness",
    "overlap",
    "ci",
    "impact",
})


class _CLIArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that fails closed with ValueError instead of exiting."""

    def error(self, message: str) -> None:
        raise ValueError(f"Argument error: {message}")


def execute_operation(operation: str, data: Any) -> dict[str, Any]:
    """Execute a canonical Repository Intelligence Core operation on parsed input data."""
    if operation == "revision":
        if not isinstance(data, dict):
            raise ValueError("Input for 'revision' must be a JSON object snapshot mapping")
        res = revision_identity(data)
        return {
            "operation": operation,
            "claim_ceiling": CLAIM_CEILING,
            "result": res.to_dict(),
        }
    elif operation == "readiness":
        if not isinstance(data, dict):
            raise ValueError("Input for 'readiness' must be a JSON object snapshot mapping")
        res = classify_readiness(data)
        return {
            "operation": operation,
            "claim_ceiling": CLAIM_CEILING,
            "result": res.to_dict(),
        }
    elif operation == "overlap":
        if isinstance(data, dict) and "snapshots" in data:
            snapshots = data["snapshots"]
        elif isinstance(data, list):
            snapshots = data
        else:
            raise ValueError("Input for 'overlap' must be an object with 'snapshots' list")
        if not isinstance(snapshots, (list, tuple)):
            raise ValueError("'snapshots' must be a list of PR snapshot mappings")
        res = analyze_cross_pr_overlap(snapshots)
        return {
            "operation": operation,
            "claim_ceiling": CLAIM_CEILING,
            "result": res.to_dict(),
        }
    elif operation == "ci":
        if not isinstance(data, dict):
            raise ValueError("Input for 'ci' must be a JSON object snapshot mapping")
        res = fingerprint_ci_failures(data)
        return {
            "operation": operation,
            "claim_ceiling": CI_EVIDENCE_CLAIM_CEILING,
            "result": res.to_dict(),
        }
    elif operation == "impact":
        if not isinstance(data, dict):
            raise ValueError("Input for 'impact' must be a JSON object graph-evidence mapping")
        res = analyze_change_impact(data)
        return {
            "operation": operation,
            "claim_ceiling": CLAIM_CEILING,
            "result": res.to_dict(),
        }
    else:
        raise ValueError(f"Unknown operation: {operation!r}. Must be one of {sorted(OPERATIONS)}")


def load_input_data(input_path: str) -> Any:
    """Load and parse JSON input from a file or stdin."""
    if input_path == "-":
        content = sys.stdin.read()
    else:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file does not exist: {input_path}")
        content = path.read_text(encoding="utf-8")

    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON input: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for repository intelligence operations."""
    try:
        parser = _CLIArgumentParser(
            prog="python -m reviewer.intelligence_cli",
            description="Repository Intelligence local JSON adapter",
            add_help=True,
        )
        parser.add_argument(
            "--operation",
            "-o",
            required=True,
            choices=sorted(OPERATIONS),
            help="Core intelligence operation to execute",
        )
        parser.add_argument(
            "--input",
            "-i",
            required=True,
            help="Path to input JSON file or '-' for stdin",
        )
        args = parser.parse_args(argv)

        raw_data = load_input_data(args.input)
        payload = execute_operation(args.operation, raw_data)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        err_payload = {
            "status": "ERROR",
            "error": str(exc),
            "claim_ceiling": CLAIM_CEILING,
        }
        print(json.dumps(err_payload, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
