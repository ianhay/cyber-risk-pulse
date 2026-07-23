#!/usr/bin/env python3
"""Validate generated data files against the JSON schemas and sanity rules.

Runs after data generation and before deployment. Fails (non-zero exit) if any
required file is missing, malformed, or violates the schema or a sanity check.
Uses jsonschema when available and falls back to structural checks otherwise.
"""
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "public" / "data"
SCHEMAS = REPO / "schemas"
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

REQUIRED = [
    "current_vulnerabilities.json", "priority_queue.json", "summary.json",
    "vendor_summary.json", "timeseries.json", "methodology.json",
    "status.json", "source_metadata.json",
]


def _load(name):
    return json.loads((DATA / name).read_text("utf-8"))


def main() -> int:
    errors = []
    for name in REQUIRED:
        if not (DATA / name).exists():
            errors.append(f"missing output: {name}")
    if errors:
        for e in errors:
            print(f"[error] {e}", file=sys.stderr)
        return 1

    records = _load("current_vulnerabilities.json")
    if not records:
        errors.append("current_vulnerabilities.json is empty")

    seen = set()
    for r in records:
        if not CVE_RE.match(r.get("id", "")):
            errors.append(f"invalid id: {r.get('id')}")
        if r["id"] in seen:
            errors.append(f"duplicate id: {r['id']}")
        seen.add(r["id"])
        if r["tier"] == "P1" and not r.get("reasons"):
            errors.append(f"{r['id']}: P1 without reason")
        cvss = r.get("cvss")
        if cvss and cvss.get("score") is not None and not (0 <= cvss["score"] <= 10):
            errors.append(f"{r['id']}: CVSS out of range")
        epss = r.get("epss")
        if epss:
            for k in ("p", "pct"):
                if epss.get(k) is not None and not (0 <= epss[k] <= 1):
                    errors.append(f"{r['id']}: EPSS {k} out of range")

    # Optional strict schema validation if jsonschema is installed.
    try:
        import jsonschema  # type: ignore

        schema = json.loads((SCHEMAS / "vulnerability.schema.json").read_text("utf-8"))
        for r in records:
            jsonschema.validate(r, schema)
        jsonschema.validate(_load("summary.json"), json.loads((SCHEMAS / "summary.schema.json").read_text("utf-8")))
        jsonschema.validate(_load("status.json"), json.loads((SCHEMAS / "status.schema.json").read_text("utf-8")))
    except ImportError:
        print("[info] jsonschema not installed; ran structural checks only")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"schema validation: {exc}")

    if errors:
        for e in errors:
            print(f"[error] {e}", file=sys.stderr)
        return 1
    print(f"validate_site: OK ({len(records)} records, {len(REQUIRED)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
