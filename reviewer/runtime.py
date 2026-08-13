"""Bounded local runtime health and recovery for unattended operation.

This module deliberately sits beside (rather than inside) the OpenCLI
transport.  Health checks are read-only.  Recovery is opt-in through an
injected daemon restart callback and is limited to the daemon-unavailable
case; browser profiles, Chrome state, cookies and extensions are never
modified here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Any


@dataclass(frozen=True)
class RuntimeHealth:
    status: str
    profile: dict | None = None
    profiles: list | None = None
    detail: str = ""
    retry_after: float = 0.0
    restart_attempted: bool = False
    restart_succeeded: bool | None = None

    @property
    def ready(self) -> bool:
        return self.status == "READY"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "profile": self.profile,
            "profiles": self.profiles,
            "detail": self.detail,
            "retry_after": self.retry_after,
            "restart_attempted": self.restart_attempted,
            "restart_succeeded": self.restart_succeeded,
        }


def _text(result: Any) -> str:
    return " ".join(str(getattr(result, name, "") or "") for name in ("status", "detail")).lower()


def classify_preflight(result: Any) -> str:
    """Map preflight output to stable service health classes."""
    status = str(getattr(result, "status", "OPENCLI_TRANSPORT_FAILURE"))
    text = _text(result)
    if status == "READY":
        return "READY"
    if status in {"OPENCLI_NOT_FOUND", "OPENCLI_DAEMON_UNAVAILABLE"}:
        return "OPENCLI_DAEMON_UNAVAILABLE"
    if status == "BROWSER_BRIDGE_REQUIRED":
        return "BROWSER_BRIDGE_REQUIRED"
    if status == "PROFILE_SELECTION_AMBIGUOUS":
        return "PROFILE_SELECTION_AMBIGUOUS"
    if status in {"CHATGPT_NOT_LOGGED_IN", "CHATGPT_LOGIN_REQUIRED"}:
        return "CHATGPT_LOGIN_REQUIRED"
    if status == "CHATGPT_CHALLENGE":
        return status
    if status == "CHATGPT_QUOTA_OR_RATE_LIMIT":
        return status
    if any(marker in text for marker in ("stale profile", "profile not found", "unknown profile", "no such profile")):
        return "STALE_PROFILE"
    if any(marker in text for marker in ("daemon", "connection refused", "bridge service unavailable")):
        return "OPENCLI_DAEMON_UNAVAILABLE"
    return "OPENCLI_TRANSPORT_FAILURE"


class RuntimeSupervisor:
    """Perform bounded health checks and optional one-shot daemon recovery.

    ``preflight`` must be a zero-prompt read-only callable (normally
    :func:`reviewer.preflight.preflight_opencli`).  ``restart_daemon`` is
    intentionally injected so callers can use their platform's already
    installed user-level daemon command without this module guessing or
    mutating machine state.
    """

    def __init__(self, preflight: Callable[[], Any], restart_daemon: Callable[[], bool] | None = None,
                 *, base_backoff: float = 5.0, max_backoff: float = 300.0):
        self.preflight = preflight
        self.restart_daemon = restart_daemon
        self.base_backoff = max(0.0, float(base_backoff))
        self.max_backoff = max(self.base_backoff, float(max_backoff))
        self._attempts = 0

    def _result(self, raw: Any, *, restart_attempted=False, restart_succeeded=None) -> RuntimeHealth:
        status = classify_preflight(raw)
        retry = 0.0 if status == "READY" else min(self.max_backoff, self.base_backoff * (2 ** self._attempts))
        return RuntimeHealth(status, getattr(raw, "profile", None), getattr(raw, "profiles", None),
                             str(getattr(raw, "detail", "") or ""), retry, restart_attempted, restart_succeeded)

    def check(self) -> RuntimeHealth:
        """Run exactly one read-only preflight; never restarts anything."""
        return self._result(self.preflight())

    def recover(self) -> RuntimeHealth:
        """Recover only daemon-unavailable health, at most once per call."""
        first = self.check()
        if first.status != "OPENCLI_DAEMON_UNAVAILABLE" or self.restart_daemon is None:
            self._attempts += 1 if not first.ready else 0
            return first
        try:
            restarted = bool(self.restart_daemon())
        except Exception as exc:  # recovery is advisory; preserve a safe state
            restarted = False
            detail = f"{first.detail}; daemon restart failed: {exc}"
        else:
            detail = first.detail
        if not restarted:
            self._attempts += 1
            return RuntimeHealth("OPENCLI_DAEMON_UNAVAILABLE", first.profile, first.profiles,
                                 detail, min(self.max_backoff, self.base_backoff * (2 ** self._attempts)), True, False)
        second = self._result(self.preflight(), restart_attempted=True, restart_succeeded=True)
        self._attempts = 0 if second.ready else self._attempts + 1
        return second


__all__ = ["RuntimeHealth", "RuntimeSupervisor", "classify_preflight"]
