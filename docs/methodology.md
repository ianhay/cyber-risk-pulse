# Methodology

## Terms

- **CVE** — a single catalogued vulnerability identifier.
- **CVSS** — a severity score (0–10) describing *impact if exploited*. Cyber
  Risk Pulse prefers the newest available version (v4.0 > v3.1 > v3.0 > v2.0)
  and uses the Primary metric where present.
- **EPSS** — the FIRST Exploit Prediction Scoring System: a daily-updated
  probability (0–1) that a CVE will be exploited in the next 30 days, plus a
  percentile ranking it against all scored CVEs. It measures *likelihood*, not
  impact.
- **KEV** — CISA's Known Exploited Vulnerabilities catalogue: vulnerabilities
  confirmed exploited in the wild. Membership is a hard, authoritative signal.

## Priority tiers

Records are placed in exactly one tier. Rules are evaluated **from P1 downward
and the first match wins**. The authoritative definitions live in
`config/priority.yml`; the in-app methodology view renders them from the same
config so the site and the pipeline can never disagree. Defaults:

| Tier | Condition (first match wins) |
| --- | --- |
| **P1** | In CISA KEV **(hard override)**, or EPSS ≥ 0.50 with CVSS ≥ 9.0 |
| **P2** | EPSS percentile ≥ 0.99, or EPSS ≥ 0.10 with CVSS ≥ 8.0, or CVSS ≥ 9.0 published within 30 days |
| **P3** | CVSS ≥ 7.0, or EPSS percentile ≥ 0.90 |
| **P4** | Everything else in scope |

Each record stores the **plain-language reasons** it landed in its tier, shown
in the detail panel.

## Missing data

If EPSS or CVSS is unavailable, the corresponding condition simply cannot match
— it is never satisfied by a default of zero. Records with missing metrics are
flagged (`no_epss`, `no_cvss`, `no_nvd_record`) and surfaced honestly in the UI.

## Scope

- A rolling NVD window (default 30 days, adjustable in `config/sources.yml`)
  bounds NVD volume.
- **All KEV entries are always included in the dataset regardless of age**, via
  direct enrichment lookups. (The client's time-window control is a separate
  user filter; widen it or use the KEV filter to see older KEV entries.)

## What this is not

These tiers are **external threat priority** — a triage signal based on public
exploitation and likelihood data. They are **not asset-specific risk**. Actual
risk depends on whether you run the affected software, how exposed it is, and
your compensating controls. CPE-derived vendor/product names can be broad;
treat affected-product lists as a starting point, not a definitive inventory
match.
