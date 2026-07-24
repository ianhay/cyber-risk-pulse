"""Load and expose the YAML configuration files.

Keeping every threshold, endpoint and label in ``config/*.yml`` means the
prioritisation logic and display terminology are visible and editable without
touching Python. The frontend receives a copy of the relevant parts via the
generated ``methodology.json`` output so the same numbers are shown to users.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

# Repository root = parent of the ingestion package.
REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"


def _load_yaml(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / name
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Config file {name} did not parse to a mapping")
    return data


@dataclass(frozen=True)
class Config:
    """Bundle of all configuration mappings plus a couple of derived helpers."""

    sources: dict[str, Any]
    priority: dict[str, Any]
    dashboard: dict[str, Any]
    vendor_aliases: dict[str, Any]

    @property
    def nvd_api_key(self) -> str | None:
        """Optional NVD API key, read only from the environment.

        In production this is provided by the ``NVD_API_KEY`` GitHub Actions
        secret. It must never be committed or embedded in the browser bundle.
        """
        key = os.environ.get("NVD_API_KEY", "").strip()
        return key or None

    def freshness_hours(self, source: str) -> tuple[float, float]:
        """Return (warn_hours, max_hours) for a source id like ``cisa_kev``."""
        fr = self.dashboard["freshness"]
        return float(fr[f"{source}_warn_hours"]), float(fr[f"{source}_max_hours"])


@lru_cache(maxsize=1)
def load_config() -> Config:
    """Load all config files once and cache the result."""
    return Config(
        sources=_load_yaml("sources.yml"),
        priority=_load_yaml("priority.yml"),
        dashboard=_load_yaml("dashboard.yml"),
        vendor_aliases=_load_yaml("vendor_aliases.yml"),
    )
