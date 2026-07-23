"""A small, dependency-light HTTP helper for the source adapters.

Provides retries with exponential backoff, a request timeout, polite spacing
between calls and an in-run response cache so a single workflow run never
fetches the same URL twice. Uses :mod:`requests` when available and falls back
to the standard library so tests can run in a minimal environment.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

try:  # pragma: no cover - exercised implicitly by environment
    import requests  # type: ignore

    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False


class HttpError(RuntimeError):
    """Raised when a request ultimately fails after all retries."""


@dataclass
class HttpClient:
    timeout: float = 30.0
    max_retries: int = 4
    backoff_base: float = 2.0
    backoff_max: float = 60.0
    user_agent: str = "cyber-risk-pulse/0.1.0"
    default_delay: float = 0.0
    # Set to a callable(seconds) in tests to avoid real sleeping.
    sleep = staticmethod(time.sleep)
    _cache: dict[str, Any] = field(default_factory=dict, repr=False)
    _last_request_at: float = field(default=0.0, repr=False)

    def _respect_spacing(self, delay: float) -> None:
        if delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_at
        wait = delay - elapsed
        if wait > 0:
            self.sleep(wait)

    def get_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        delay: float | None = None,
        cache: bool = True,
    ) -> Any:
        """GET a URL and parse JSON, with retries and optional caching."""
        full_url = url
        if params:
            full_url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
        if cache and full_url in self._cache:
            return self._cache[full_url]

        merged_headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if headers:
            merged_headers.update(headers)

        spacing = self.default_delay if delay is None else delay
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._respect_spacing(spacing)
            self._last_request_at = time.monotonic()
            try:
                data = self._raw_get_json(full_url, merged_headers)
                if cache:
                    self._cache[full_url] = data
                return data
            except Exception as exc:  # noqa: BLE001 - want to retry on any transport error
                last_exc = exc
                if attempt >= self.max_retries:
                    break
                backoff = min(self.backoff_base * (2**attempt), self.backoff_max)
                self.sleep(backoff)
        raise HttpError(f"GET {url} failed after {self.max_retries + 1} attempts: {last_exc}")

    def get_text(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        delay: float | None = None,
        cache: bool = True,
    ) -> str:
        if cache and url in self._cache:
            return self._cache[url]
        merged_headers = {"User-Agent": self.user_agent}
        if headers:
            merged_headers.update(headers)
        spacing = self.default_delay if delay is None else delay
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._respect_spacing(spacing)
            self._last_request_at = time.monotonic()
            try:
                text = self._raw_get_text(url, merged_headers)
                if cache:
                    self._cache[url] = text
                return text
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt >= self.max_retries:
                    break
                backoff = min(self.backoff_base * (2**attempt), self.backoff_max)
                self.sleep(backoff)
        raise HttpError(f"GET {url} failed after {self.max_retries + 1} attempts: {last_exc}")

    # --- transport backends -------------------------------------------------

    def _raw_get_json(self, url: str, headers: dict[str, str]) -> Any:
        if _HAVE_REQUESTS:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json()
        return json.loads(self._urllib_get(url, headers))

    def _raw_get_text(self, url: str, headers: dict[str, str]) -> str:
        if _HAVE_REQUESTS:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            return resp.text
        return self._urllib_get(url, headers)

    def _urllib_get(self, url: str, headers: dict[str, str]) -> str:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            status = getattr(resp, "status", 200)
            if status >= 400:
                raise HttpError(f"HTTP {status} for {url}")
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset)
