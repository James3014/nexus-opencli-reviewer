"""Static data configuration and zero-call preflight contract for hosted risk provider.

This module defines the schema and loader for hosted provider private config.
Private config is strictly DATA, NOT CODE. No dynamic code loading, no shell
execution, no default endpoints/keys, HTTPS only, exact host whitelist matching,
environment variable name validation (never secret values), and zero network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

_ENV_VAR_NAME_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_CANONICAL_CONFIG_KEYS = {
    "endpoint_origin",
    "api_key_env_var_name",
    "max_canary_quota",
    "allowed_hosts_whitelist",
}


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON objects instead of silently keeping the last key."""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("config.json contains duplicate JSON keys")
        result[key] = value
    return result


class HostedPreflightStatus(str, Enum):
    VALID = "VALID"
    CONFIG_UNAVAILABLE = "CONFIG_UNAVAILABLE"
    CONFIG_INVALID = "CONFIG_INVALID"


@dataclass(frozen=True)
class HostedProviderConfigV1:
    """Immutable, typed private configuration for hosted risk provider."""

    endpoint_origin: str
    api_key_env_var_name: str
    max_canary_quota: int
    allowed_hosts_whitelist: tuple[str, ...]

    def __post_init__(self) -> None:
        # endpoint_origin validation: HTTPS only, exact origin without path, query, fragment, userinfo
        if not isinstance(self.endpoint_origin, str) or not self.endpoint_origin.strip():
            raise ValueError("endpoint_origin must be a non-empty string")

        origin = self.endpoint_origin.strip()
        if "?" in origin:
            raise ValueError("endpoint_origin must not contain a query marker")
        if "#" in origin:
            raise ValueError("endpoint_origin must not contain a fragment marker")

        parsed = urlparse(origin)

        if parsed.scheme != "https":
            raise ValueError(f"endpoint_origin must use HTTPS scheme, got {parsed.scheme!r}")

        if parsed.username or parsed.password:
            raise ValueError("endpoint_origin must not contain userinfo/credentials")

        if parsed.path not in ("", "/"):
            raise ValueError(f"endpoint_origin must not contain path beyond '/', got {parsed.path!r}")

        if parsed.query:
            raise ValueError(f"endpoint_origin must not contain query parameters, got {parsed.query!r}")

        if parsed.fragment:
            raise ValueError(f"endpoint_origin must not contain fragment, got {parsed.fragment!r}")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("endpoint_origin must contain a valid hostname")

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("endpoint_origin contains an invalid port") from exc
        if port == 0 or (port is None and parsed.netloc.endswith(":")):
            raise ValueError("endpoint_origin contains an invalid port")

        # api_key_env_var_name validation: valid identifier, no secret values
        if not isinstance(self.api_key_env_var_name, str) or not self.api_key_env_var_name.strip():
            raise ValueError("api_key_env_var_name must be a non-empty string")

        env_name = self.api_key_env_var_name.strip()
        if not _ENV_VAR_NAME_PATTERN.fullmatch(env_name):
            raise ValueError(
                f"api_key_env_var_name {env_name!r} must match pattern {_ENV_VAR_NAME_PATTERN.pattern}"
            )

        # max_canary_quota validation: strictly integer > 0, not bool
        if isinstance(self.max_canary_quota, bool) or not isinstance(self.max_canary_quota, int):
            raise ValueError("max_canary_quota must be an integer, not bool")

        if self.max_canary_quota <= 0:
            raise ValueError(f"max_canary_quota must be > 0, got {self.max_canary_quota}")

        # allowed_hosts_whitelist validation: non-empty, unique, exact host values, no wildcards
        if not isinstance(self.allowed_hosts_whitelist, (list, tuple)):
            raise ValueError("allowed_hosts_whitelist must be a sequence of host strings")

        hosts_tuple = tuple(self.allowed_hosts_whitelist)
        if not hosts_tuple:
            raise ValueError("allowed_hosts_whitelist must not be empty")

        if len(set(hosts_tuple)) != len(hosts_tuple):
            raise ValueError("allowed_hosts_whitelist contains duplicate entries")

        for host in hosts_tuple:
            if not isinstance(host, str) or not host.strip():
                raise ValueError("allowed_hosts_whitelist entries must be non-empty strings")
            h = host.strip()
            if h != host or any(char.isspace() for char in h):
                raise ValueError(
                    "allowed_hosts_whitelist entries must not contain surrounding or control whitespace"
                )
            if "*" in h or "/" in h or ":" in h or "\\" in h:
                raise ValueError("allowed_hosts_whitelist entry contains invalid characters or wildcard")
            if h.startswith(".") or h.endswith("."):
                raise ValueError(f"allowed_hosts_whitelist entry {h!r} must not start or end with dot")

        # Check exact whitelist match
        if hostname not in hosts_tuple:
            raise ValueError(f"Hostname {hostname!r} is not in allowed_hosts_whitelist {hosts_tuple!r}")

        # Freeze fields cleanly
        object.__setattr__(self, "endpoint_origin", origin.rstrip("/"))
        object.__setattr__(self, "api_key_env_var_name", env_name)
        object.__setattr__(self, "allowed_hosts_whitelist", hosts_tuple)

    def canonical_config_hash(self) -> str:
        """Compute deterministic SHA-256 hash over canonical JSON representation."""
        payload = {
            "allowed_hosts_whitelist": list(self.allowed_hosts_whitelist),
            "api_key_env_var_name": self.api_key_env_var_name,
            "endpoint_origin": self.endpoint_origin,
            "max_canary_quota": self.max_canary_quota,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class HostedProviderPreflightV1:
    """Preflight evaluation result for hosted provider configuration (zero network calls)."""

    status: HostedPreflightStatus
    config_hash: str | None
    endpoint_origin: str | None
    endpoint_host: str | None
    max_canary_quota: int | None
    credential_name_present: bool
    error_message: str | None = None


def load_hosted_provider_config_from_dict(data: Any) -> HostedProviderConfigV1:
    """Parse and validate HostedProviderConfigV1 from a dictionary.

    Fails closed on unknown fields, missing fields, or invalid types.
    """
    if type(data) is not dict:
        raise ValueError("Configuration must be an exact JSON object")

    keys = set(data.keys())
    if keys != _CANONICAL_CONFIG_KEYS:
        missing = _CANONICAL_CONFIG_KEYS - keys
        extra = keys - _CANONICAL_CONFIG_KEYS
        errors = []
        if missing:
            errors.append(f"missing required fields: {sorted(list(missing))}")
        if extra:
            errors.append(f"unknown fields forbidden: {sorted(list(extra))}")
        raise ValueError("; ".join(errors))

    raw_hosts = data["allowed_hosts_whitelist"]
    if type(raw_hosts) not in (list, tuple):
        raise ValueError("allowed_hosts_whitelist must be a JSON array or tuple")

    return HostedProviderConfigV1(
        endpoint_origin=data["endpoint_origin"],
        api_key_env_var_name=data["api_key_env_var_name"],
        max_canary_quota=data["max_canary_quota"],
        allowed_hosts_whitelist=tuple(raw_hosts),
    )


def load_hosted_provider_config_from_root(private_eval_root: str | Path | None) -> HostedProviderConfigV1:
    """Load config.json from an explicitly provided private evaluation root directory.

    Strict filesystem safety:
    - Root directory must exist.
    - Resolves exact '<root>/config.json'.
    - Rejects directory traversal or symlinks escaping the private root.
    - UTF-8 decoding.
    - Static JSON data only.
    """
    if private_eval_root is None:
        raise ValueError("private_eval_root must be explicitly provided")

    root_path = Path(private_eval_root).resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise ValueError(f"private_eval_root directory does not exist or is not a directory: {root_path}")

    config_file = root_path / "config.json"
    if not config_file.exists():
        raise FileNotFoundError(f"config.json not found in private_eval_root: {config_file}")

    # Check symlink escape
    if config_file.is_symlink():
        target = config_file.resolve()
        try:
            target.relative_to(root_path)
        except ValueError:
            raise ValueError(f"config.json is a symlink pointing outside private_eval_root: {target}")

    if not config_file.is_file():
        raise ValueError(f"config.json is not a regular file: {config_file}")

    try:
        raw_bytes = config_file.read_bytes()
        text = raw_bytes.decode("utf-8")
        data = json.loads(text, object_pairs_hook=_reject_duplicate_object_pairs)
    except UnicodeDecodeError as exc:
        raise ValueError(f"config.json is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"config.json is not valid JSON: {exc}") from exc

    return load_hosted_provider_config_from_dict(data)


def run_hosted_provider_zero_call_preflight(
    private_eval_root: str | Path | None = None,
    *,
    config: HostedProviderConfigV1 | None = None,
) -> HostedProviderPreflightV1:
    """Execute zero-call preflight checks against hosted provider configuration.

    Zero network primitives are invoked.
    """
    if config is not None and private_eval_root is not None:
        return HostedProviderPreflightV1(
            status=HostedPreflightStatus.CONFIG_INVALID,
            config_hash=None,
            endpoint_origin=None,
            endpoint_host=None,
            max_canary_quota=None,
            credential_name_present=False,
            error_message="provide exactly one config source: private_eval_root or config",
        )

    if config is not None:
        if type(config) is not HostedProviderConfigV1:
            return HostedProviderPreflightV1(
                status=HostedPreflightStatus.CONFIG_INVALID,
                config_hash=None,
                endpoint_origin=None,
                endpoint_host=None,
                max_canary_quota=None,
                credential_name_present=False,
                error_message="config must be an exact HostedProviderConfigV1 instance",
            )
        cfg = HostedProviderConfigV1(
            endpoint_origin=config.endpoint_origin,
            api_key_env_var_name=config.api_key_env_var_name,
            max_canary_quota=config.max_canary_quota,
            allowed_hosts_whitelist=config.allowed_hosts_whitelist,
        )
    else:
        try:
            cfg = load_hosted_provider_config_from_root(private_eval_root)
        except FileNotFoundError as exc:
            return HostedProviderPreflightV1(
                status=HostedPreflightStatus.CONFIG_UNAVAILABLE,
                config_hash=None,
                endpoint_origin=None,
                endpoint_host=None,
                max_canary_quota=None,
                credential_name_present=False,
                error_message=str(exc),
            )
        except Exception as exc:
            return HostedProviderPreflightV1(
                status=HostedPreflightStatus.CONFIG_INVALID,
                config_hash=None,
                endpoint_origin=None,
                endpoint_host=None,
                max_canary_quota=None,
                credential_name_present=False,
                error_message=str(exc),
            )

    parsed = urlparse(cfg.endpoint_origin)
    return HostedProviderPreflightV1(
        status=HostedPreflightStatus.VALID,
        config_hash=cfg.canonical_config_hash(),
        endpoint_origin=cfg.endpoint_origin,
        endpoint_host=parsed.hostname,
        max_canary_quota=cfg.max_canary_quota,
        credential_name_present=bool(cfg.api_key_env_var_name),
        error_message=None,
    )
