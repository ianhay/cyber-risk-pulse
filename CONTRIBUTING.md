# Contributing

Thanks for your interest in improving Cyber Risk Pulse.

## Ground rules

- **No secrets in the repo or the browser.** The only credential is the optional
  `NVD_API_KEY`, read from the environment in CI. Never hard-code it.
- **Missing data is never zero.** Absent EPSS/CVSS must stay `null` and surface
  as unavailable. Priority rules must not treat missing values as satisfying a
  threshold.
- **KEV is authoritative.** KEV membership always forces P1 and KEV records must
  never be silently dropped.
- **The data contract is law.** If you change a published field, update
  `schemas/`, the TypeScript `src/types`, `docs/data_dictionary.md`, and the
  tests together.

## Development

```bash
pip install -e ".[dev]"
npm install
npm run data:fixture     # offline data
npm run dev
```

## Before opening a PR

```bash
python -m pytest        # Python ingestion tests
npm run typecheck       # TypeScript
npm test                # frontend unit tests
npm run build           # production build must succeed
python scripts/validate_site.py
```

## Where things live

- A new or changed upstream format → the relevant adapter in
  `ingestion/sources/`, with tests and a fixture update.
- Priority logic → `config/priority.yml` and `ingestion/priority.py`; add
  boundary tests in `tests/test_priority.py`.
- UI behaviour → `src/`; keep upstream text rendered via `textContent` (see
  `src/components/dom.ts`) so feed data can never inject markup.

## Ideas for v0.2+

Tree-shaken ECharts imports, Playwright end-to-end tests, virtualised table
rendering, a configurable watchlist view, and an accessibility audit pass.
