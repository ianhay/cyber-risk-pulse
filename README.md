# Cyber Risk Pulse

An open-data dashboard that tracks **which vulnerabilities are actually being exploited or are most likely to be**, and turns that into a small set of transparent threat-priority tiers. It combines three public feeds — **CISA KEV**, **NVD (NIST)** and **FIRST EPSS** — prepares them server-side on a schedule, and serves a fast static site with no backend and no secrets in the browser.

> Cyber Risk Pulse describes **external threat priority**, not asset-specific risk. It cannot know what you run or how it is exposed. Always confirm applicability against your own inventory.

![status: fixture demo data ships in the repo](https://img.shields.io/badge/data-demo%20included-38BDC9)

---

## What it shows

- **Priority queue** — every in-scope CVE placed in exactly one tier (P1–P4), P1 first, each row carrying its tier as colour **and** a mono code **and** text (never colour alone).
- **KPIs** — new CVEs and new KEV in the window, P1 count, critical-severity count, high-EPSS count, and the full KEV catalogue total.
- **Signals** — volume over time, tier and severity distributions, EPSS probability histogram, top vendors, and time-from-publish-to-KEV. Every chart reflects the active filters.
- **Detail panel** — full description, plain-language reasons for the tier, CVSS vector, EPSS score and percentile, KEV required action, CWEs, affected products (with a matching-caveat), and trusted references.
- **Methodology view** — the exact rules, thresholds and sources, generated from the same config that drives the pipeline.

## How priority is decided

Rules are evaluated from P1 downward; the first match wins. **CISA KEV membership always forces P1.** Missing EPSS or CVSS is shown as unavailable and never treated as zero. The precise thresholds live in `config/priority.yml` and are surfaced in the in-app methodology view — see [docs/methodology.md](docs/methodology.md).

## Architecture in one line

GitHub Actions runs Python adapters against the three feeds → validates and priority-scores the data → writes compact static JSON into `public/data` → Vite builds a static site → GitHub Pages serves it → the browser reads only the prepared JSON. Full diagram in [docs/architecture.md](docs/architecture.md).

The browser **never** calls NVD directly, and no API key is ever shipped to the client.

---

## Quick start (local)

Requirements: Node 20+ and Python 3.10+.

```bash
# 1. Install
npm install
pip install -e .

# 2. Generate data from the bundled fixtures (no network needed)
npm run data:fixture

# 3. Run the dev server
npm run dev
```

The repo ships with a **demo dataset** already generated in `public/data`, so `npm run dev` works immediately even before step 2.

### Useful scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Vite dev server |
| `npm run build` | Typecheck + production build to `dist/` |
| `npm test` | Frontend unit tests (Vitest) |
| `npm run data:fixture` | Build data from offline fixtures |
| `npm run data:live` | Fetch from live CISA/NVD/EPSS |
| `npm run data:validate` | Validate generated data against schemas |
| `python -m pytest` | Python ingestion test suite |

---

## Deploying to GitHub Pages

1. Push this repository to GitHub.
2. In **Settings → Pages**, set **Source: GitHub Actions**.
3. (Recommended) Add an NVD API key as a repository secret named `NVD_API_KEY` (request one free at the NVD site). Without it the pipeline still runs, just more slowly.
4. The `refresh-and-deploy` workflow runs twice daily and can be triggered manually from the **Actions** tab. It fetches live data, validates it, builds the site, and deploys.

### Project Pages vs user Pages

- **Project Pages** (`username.github.io/cyber-risk-pulse/`): the deploy workflow sets `VITE_BASE` to `/<repo>/` automatically.
- **User/org Pages** (`username.github.io`): set `VITE_BASE` to `/` in the build step.

### Last-known-good protection

The deploy workflow caches the previously published `public/data`. If a source fails or the record count collapses by more than half, the pipeline keeps the prior data, marks the run **Degraded/Stale**, and the site shows a banner rather than publishing empty data.

---

## Project layout

```
config/          Authoritative YAML: endpoints, priority rules, thresholds, terminology
ingestion/       Python package: source adapters, join, priority engine, outputs
  sources/       One isolated, tested adapter per feed (cisa_kev, nvd, epss)
schemas/         JSON Schemas for the published data contract
scripts/         refresh_data (live), build_fixture_site (offline), validate_site
tests/           pytest suite + coherent JSON fixtures
public/data/     Generated static data (committed as a demo dataset)
public/config/   Optional watchlist.example.json
src/             Frontend (TypeScript + Vite + ECharts, no heavy framework)
  data/          load + pure derive functions + reactive store
  components/    header, KPIs, detail panel, formatting, DOM helper
  charts/        ECharts wiring (theme-aware, filter-driven)
  filters/       filter bar
  table/         priority queue table
  methodology/   methodology view
docs/            architecture, methodology, data dictionary, source licences
.github/workflows/  CI, scheduled refresh + Pages deploy, dependency review
```

## Documentation

- [Architecture](docs/architecture.md)
- [Methodology](docs/methodology.md)
- [Data dictionary](docs/data_dictionary.md)
- [Source licences & attribution](docs/source_licences.md)
- [Contributing](CONTRIBUTING.md)

## Data sources & attribution

Built entirely on public data from CISA (KEV), NIST (NVD) and FIRST (EPSS). This project is **not affiliated with or endorsed by** any of them. See [docs/source_licences.md](docs/source_licences.md) for terms and attribution.

## Licence

Code is released under the [MIT Licence](LICENSE). Upstream data remains under its own terms.
