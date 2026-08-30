"""Repository Intelligence CLI compatibility projection.

Compatibility projection to canonical repository_intelligence.cli.
Deterministic, pure local JSON adapter for Repository Intelligence Core V1 operations.
No GitHub/network/state writes.
Claim ceiling: ADAPTER_ONLY.
"""
from __future__ import annotations

import sys

from repository_intelligence.cli import (
    CI_EVIDENCE_CLAIM_CEILING,
    CLAIM_CEILING,
    OPERATIONS,
    execute_operation,
    load_input_data,
    main,
)

if __name__ == "__main__":
    sys.exit(main())
