"""FIRST EPSS adapter.

Retrieves current EPSS probability and percentile for a set of CVE ids in
batches. Values are stored as decimals in [0, 1]; conversion to percentages
happens only in the presentation layer. Missing EPSS data is represented by
``None`` and flagged, never substituted with zero.

Fetching is deliberately bounded: batches are spaced out, a batch that fails is
skipped rather than retried into a storm, and the whole stage stops once a
wall-clock budget is spent. FIRST throttles bursts, so an unbounded loop of
back-to-back requests can otherwise stall the pipeline for many minutes. CVEs
whose EPSS is skipped simply show as unavailable (never zero).
"""
from __future__ import annotations

import sys
import time
from typing import Any, Iterable

from ..http import HttpClient
from ..models import EpssScore


def parse_epss_response(payload: dict[str, Any]) -> dict[str, EpssScore]:
    """Parse an EPSS API response into a CVE id -> :class:`EpssScore` map."""
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError("EPSS payload missing 'data' list")
    out: dict[str, EpssScore] = {}
    for row in data:
        cve = str(row.get("cve", "")).strip()
        if not cve:
            continue
        out[cve] = EpssScore(
            probability=_as_float(row.get("epss")),
            percentile=_as_float(row.get("percentile")),
            score_date=row.get("date"),
        )
    return out


def fetch_epss(
    client: HttpClient,
    base_url: str,
    cve_ids: Iterable[str],
    *,
    batch_size: int,
    delay: float = 0.3,
    time_budget: float | None = 120.0,
) -> dict[str, EpssScore]:
    """Fetch current EPSS scores for the given CVE ids using batched requests.

    ``delay`` spaces batches out so FIRST does not throttle the burst.
    ``time_budget`` (seconds) caps the whole stage: if it is exceeded the loop
    stops and the CVEs not yet fetched are left without EPSS (shown as n/a),
    rather than allowing a throttling episode to stall the deploy. A batch that
    errors is logged and skipped, never retried into a storm.
    """
    ids = [c for c in dict.fromkeys(cve_ids)]  # dedupe, preserve order
    scores: dict[str, EpssScore] = {}
    started = time.monotonic()
    batches = _chunks(ids, batch_size)
    for index, batch in enumerate(batches):
        if time_budget is not None and (time.monotonic() - started) > time_budget:
            remaining = len(batches) - index
            print(
                f"[warn] EPSS time budget ({time_budget:.0f}s) reached; skipping "
                f"{remaining} remaining batch(es). Affected CVEs show EPSS as n/a.",
                file=sys.stderr,
            )
            break
        try:
            payload = client.get_json(base_url, params={"cve": ",".join(batch)}, delay=delay)
            scores.update(parse_epss_response(payload))
        except Exception as exc:  # noqa: BLE001 - EPSS is best-effort enrichment
            print(f"[warn] EPSS batch {index + 1} failed, skipping: {exc}", file=sys.stderr)
            continue
    return scores


def _chunks(items: list[str], size: int) -> list[list[str]]:
    if size < 1:
        size = 1
    return [items[i : i + size] for i in range(0, len(items), size)]


def _as_float(value: Any) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    # EPSS values are decimals in [0, 1]; guard against stray out-of-range data.
    if f < 0 or f > 1:
        return None
    return f
