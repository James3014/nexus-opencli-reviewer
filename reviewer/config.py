"""Configuration for the unattended Reviewer service.

The configuration is deliberately boring: a local JSON document, validated at
load time, with no credentials or browser state.  Keeping validation here
means the polling service can fail before it starts making network calls.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "nexus-opencli-reviewer" / "config.json"
DEFAULT_STATE_ROOT = Path.home() / ".local" / "state" / "nexus-opencli-reviewer"
DEFAULT_LOG_PATH = DEFAULT_STATE_ROOT / "reviewer.log"
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BOOTSTRAP_MODES = {"new_only", "bounded"}


class ConfigError(ValueError):
    """Raised when operator configuration is unsafe or malformed."""


@dataclass(frozen=True)
class BootstrapPolicy:
    """Controls treatment of PRs already open at service activation."""

    mode: str = "new_only"
    max_reviews: int = 0

    def __post_init__(self) -> None:
        mode = str(self.mode).strip().lower()
        if mode not in _BOOTSTRAP_MODES:
            raise ConfigError(f"bootstrap.mode must be one of {sorted(_BOOTSTRAP_MODES)}")
        if isinstance(self.max_reviews, bool) or int(self.max_reviews) < 0:
            raise ConfigError("bootstrap.max_reviews must be a non-negative integer")
        if mode == "new_only" and int(self.max_reviews) != 0:
            raise ConfigError("bootstrap.max_reviews must be 0 when mode is new_only")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "max_reviews", int(self.max_reviews))

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "max_reviews": self.max_reviews}


@dataclass(frozen=True)
class ReviewerConfig:
    """Validated local service settings.

    Semantic concurrency is intentionally fixed at one.  A future change may
    raise that bound only with new transport/quota evidence and tests.
    """

    repositories: tuple[str, ...] = ("James3014/Nexus-new",)
    poll_interval_seconds: float = 60.0
    publication_enabled: bool = True
    semantic_concurrency: int = 1
    bootstrap: BootstrapPolicy = field(default_factory=BootstrapPolicy)
    state_root: Path = DEFAULT_STATE_ROOT
    log_path: Path = DEFAULT_LOG_PATH
    opencli_executable: str = "/Users/jameschen/.npm-global/bin/opencli"

    def __post_init__(self) -> None:
        repos = tuple(str(r).strip() for r in self.repositories)
        if not repos or any(not _REPOSITORY.fullmatch(r) for r in repos):
            raise ConfigError("repositories must contain owner/name values")
        if len(set(repos)) != len(repos):
            raise ConfigError("repositories must not contain duplicates")
        try:
            interval = float(self.poll_interval_seconds)
        except (TypeError, ValueError) as exc:
            raise ConfigError("poll_interval_seconds must be a number") from exc
        if interval < 5 or interval > 86400:
            raise ConfigError("poll_interval_seconds must be between 5 and 86400")
        if isinstance(self.semantic_concurrency, bool) or int(self.semantic_concurrency) != 1:
            raise ConfigError("semantic_concurrency is fixed at 1")
        if not isinstance(self.publication_enabled, bool):
            raise ConfigError("publication_enabled must be boolean")
        object.__setattr__(self, "repositories", repos)
        object.__setattr__(self, "poll_interval_seconds", interval)
        object.__setattr__(self, "semantic_concurrency", 1)
        object.__setattr__(self, "state_root", _safe_path(self.state_root, "state_root"))
        object.__setattr__(self, "log_path", _safe_path(self.log_path, "log_path"))
        if not str(self.opencli_executable).strip():
            raise ConfigError("opencli_executable must not be empty")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ReviewerConfig":
        if not isinstance(raw, Mapping):
            raise ConfigError("configuration must be a JSON object")
        repos = raw.get("repositories", raw.get("repos", cls.repositories))
        if isinstance(repos, str):
            repos = [repos]
        bootstrap_raw = raw.get("bootstrap", raw.get("bootstrap_policy", {}))
        if isinstance(bootstrap_raw, str):
            bootstrap_raw = {"mode": bootstrap_raw}
        if not isinstance(bootstrap_raw, Mapping):
            raise ConfigError("bootstrap must be an object")
        mode = str(bootstrap_raw.get("mode", "new_only")).lower()
        max_default = 0 if mode == "new_only" else 1
        bootstrap = BootstrapPolicy(mode=mode, max_reviews=bootstrap_raw.get("max_reviews", max_default))
        publication = raw.get("publication_enabled", raw.get("publication", True))
        if isinstance(publication, Mapping):
            publication = publication.get("enabled", True)
        return cls(
            repositories=tuple(repos) if isinstance(repos, (list, tuple)) else repos,
            poll_interval_seconds=raw.get("poll_interval_seconds", raw.get("poll_interval", 60)),
            publication_enabled=publication,
            semantic_concurrency=raw.get("semantic_concurrency", raw.get("concurrency", 1)),
            bootstrap=bootstrap,
            state_root=raw.get("state_root", DEFAULT_STATE_ROOT),
            log_path=raw.get("log_path", DEFAULT_LOG_PATH),
            opencli_executable=raw.get("opencli_executable", "/Users/jameschen/.npm-global/bin/opencli"),
        )

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "ReviewerConfig":
        target = Path(path).expanduser()
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot load config {target}: {exc}") from exc
        return cls.from_mapping(raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repositories": list(self.repositories),
            "poll_interval_seconds": self.poll_interval_seconds,
            "publication_enabled": self.publication_enabled,
            "semantic_concurrency": 1,
            "bootstrap": self.bootstrap.to_dict(),
            "state_root": str(self.state_root),
            "log_path": str(self.log_path),
            "opencli_executable": self.opencli_executable,
        }


def _safe_path(value: str | os.PathLike[str], field_name: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ConfigError(f"{field_name} must be a local path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ConfigError(f"{field_name} must be an absolute path")
    return path


def load_config(path: str | os.PathLike[str] | None = None) -> ReviewerConfig:
    """Load a config file, or return safe defaults when it does not exist."""

    target = Path(path).expanduser() if path is not None else DEFAULT_CONFIG_PATH
    if not target.exists():
        return ReviewerConfig()
    return ReviewerConfig.from_file(target)


def save_config(config: ReviewerConfig, path: str | os.PathLike[str] | None = None) -> Path:
    """Write a validated config document with restrictive local permissions."""

    target = Path(path).expanduser() if path is not None else DEFAULT_CONFIG_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return target


__all__ = ["BootstrapPolicy", "ConfigError", "ReviewerConfig", "load_config", "save_config"]
