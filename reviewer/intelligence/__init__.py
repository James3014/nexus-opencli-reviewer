"""Legacy Repository Intelligence compatibility shim.

The canonical implementation lives in :mod:`repository_intelligence`.
This package path remains import-compatible for existing consumers but owns no
classifier, overlap, readiness, CI, CFI, EIA, or report-building logic.
"""
from __future__ import annotations

from repository_intelligence import *  # noqa: F401,F403
from repository_intelligence import __all__ as __all__
