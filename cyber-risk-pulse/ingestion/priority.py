"""Transparent priority-tier assignment.

Evaluates the rules in ``config/priority.yml`` against a canonical
:class:`Vulnerability`. A record receives the first tier (p1 -> p4) whose
condition set matches. Every match records plain-language reasons, and KEV
membership is a hard override to P1. Missing EPSS or CVSS never counts as
zero: a condition that needs a value the record lacks simply does not match.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import PriorityInfo, Vulnerability

_TIER_ORDER = ["p1", "p2", "p3", "p4"]


class PriorityEngine:
    def __init__(self, priority_config: dict[str, Any]) -> None:
        self.rules = priority_config["priority_rules"]
        self.kev_forces_p1 = bool(priority_config.get("kev_forces_p1", True))

    def assign(self, vuln: Vulnerability, now: datetime | None = None) -> PriorityInfo:
        now = now or datetime.now(timezone.utc)

        # Hard override: KEV always maps to P1.
        if self.kev_forces_p1 and vuln.kev.is_kev:
            return PriorityInfo(tier="P1", reasons=self._reasons(vuln, now, forced_kev=True))

        for tier_key in _TIER_ORDER:
            rule = self.rules.get(tier_key)
            if rule is None:
                continue
            if rule.get("default"):
                return PriorityInfo(tier=tier_key.upper(), reasons=["Did not meet a higher tier"])
            if self._matches(rule, vuln, now):
                return PriorityInfo(
                    tier=tier_key.upper(), reasons=self._reasons(vuln, now)
                )
        return PriorityInfo(tier="P4", reasons=["Did not meet a higher tier"])

    # --- rule evaluation ----------------------------------------------------

    def _matches(self, rule: dict[str, Any], vuln: Vulnerability, now: datetime) -> bool:
        if "any" in rule:
            return any(self._matches(c, vuln, now) for c in rule["any"])
        if "all" in rule:
            return all(self._matches(c, vuln, now) for c in rule["all"])
        # Leaf condition (single key/value).
        return all(self._leaf(k, v, vuln, now) for k, v in rule.items())

    def _leaf(self, key: str, value: Any, vuln: Vulnerability, now: datetime) -> bool:
        if key == "kev":
            return vuln.kev.is_kev is bool(value)
        if key == "epss_gte":
            p = vuln.epss.probability if vuln.epss else None
            return p is not None and p >= value
        if key == "epss_percentile_gte":
            p = vuln.epss.percentile if vuln.epss else None
            return p is not None and p >= value
        if key == "cvss_gte":
            s = vuln.cvss.base_score if vuln.cvss else None
            return s is not None and s >= value
        if key == "published_within_days":
            if vuln.published_at is None:
                return False
            age_days = (now - vuln.published_at).total_seconds() / 86400.0
            return 0 <= age_days <= value
        # Unknown condition keys never match (fail closed).
        return False

    # --- reason strings -----------------------------------------------------

    def _reasons(self, vuln: Vulnerability, now: datetime, forced_kev: bool = False) -> list[str]:
        reasons: list[str] = []
        if vuln.kev.is_kev:
            reasons.append("Listed in CISA KEV (known exploited)")
            if (vuln.kev.known_ransomware_campaign_use or "").lower() == "known":
                reasons.append("Known ransomware campaign use")
        if vuln.cvss and vuln.cvss.base_score is not None:
            sev = f" {vuln.cvss.severity}" if vuln.cvss.severity else ""
            reasons.append(f"CVSS {vuln.cvss.base_score:g}{sev} (v{vuln.cvss.version})")
        if vuln.epss and vuln.epss.probability is not None:
            reasons.append(f"EPSS {vuln.epss.probability * 100:.1f}% probability")
        if vuln.epss and vuln.epss.percentile is not None:
            reasons.append(f"EPSS {vuln.epss.percentile * 100:.1f} percentile")
        if vuln.published_at is not None:
            age_days = int((now - vuln.published_at).total_seconds() / 86400.0)
            if 0 <= age_days <= 30:
                reasons.append(f"Published recently ({age_days}d ago)")
        if not reasons:
            reasons.append("Meets tier thresholds")
        return reasons
