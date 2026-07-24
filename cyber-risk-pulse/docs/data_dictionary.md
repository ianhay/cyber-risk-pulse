# Data dictionary

Generated files live in `public/data`. All records conform to the schemas in
`schemas/`.

## current_vulnerabilities.json

Array of compact vulnerability records.

| Field | Type | Source | Notes |
| --- | --- | --- | --- |
| `id` | string | NVD/KEV | CVE identifier, validated `CVE-YYYY-NNNN+` |
| `desc` | string | NVD/KEV | English description |
| `published` | string/null | NVD | ISO 8601 UTC |
| `modified` | string/null | NVD | ISO 8601 UTC |
| `status` | string/null | NVD | e.g. Analyzed, Awaiting Analysis |
| `vendors` | string[] | NVD CPE | Normalised display names |
| `vendorsRaw` | string[] | NVD CPE | Raw CPE vendor tokens |
| `products` | string[] | NVD CPE | Product tokens |
| `cwes` | string[] | NVD | CWE identifiers |
| `cvss` | object/null | NVD | `{version, score, severity, vector, source}`; null when unavailable |
| `epss` | object/null | EPSS | `{p, pct, date}`; probability and percentile in [0,1] |
| `kev` | object/null | CISA KEV | `{isKev, vendorProject, product, name, dateAdded, dueDate, requiredAction, ransomware}` |
| `tier` | string | derived | P1–P4 |
| `reasons` | string[] | derived | Plain-language rationale |
| `refs` | object[] | NVD | `{url, source}` |
| `flags` | string[] | derived | e.g. `no_epss`, `no_cvss`, `no_nvd_record` |

## priority_queue.json

The same records, pre-sorted P1→P4 for the default table view.

## summary.json

`window_days`, `generated_at`, `kpis` (integer counts), `tier_counts`,
`severity_counts`.

## vendor_summary.json

Vendor aggregates, including `top_by_total` used by the vendors chart.

## timeseries.json

Per-day counts of new CVEs and new KEV additions, plus time-to-KEV pairs.

## status.json

`overall_status` (Current/Degraded/Stale), `generated_at`, `app_version`,
`build_commit`, `fixture_mode`, `freshness` thresholds, and per-`sources`
health including `used_last_known_good`.

## methodology.json

Terminology, priority rules, tier labels, thresholds, time windows and source
descriptions — the single source of truth rendered by the methodology view.

## source_metadata.json

Per-source retrieval metadata: endpoint, fetch time, record counts.

## history.csv

One row per run day (same-day re-runs replace the row): date and tier counts,
for long-run trend tracking.
