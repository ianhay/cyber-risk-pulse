# Source licences & attribution

Cyber Risk Pulse is built entirely on public data. It is **not affiliated with
or endorsed by** CISA, NIST or FIRST. Confirm current terms at the source before
redistributing derived data.

## CISA Known Exploited Vulnerabilities (KEV)

- Feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Produced by the U.S. Cybersecurity and Infrastructure Security Agency. U.S.
  Government works are generally not subject to domestic copyright. Attribute to
  CISA and do not imply endorsement.

## NVD — National Vulnerability Database (NIST)

- API: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Produced by NIST. Attribute to NIST/NVD. NVD requests a courteous request rate
  and offers a free API key to raise limits; this project reads that key only in
  CI via the `NVD_API_KEY` secret. This product uses the NVD API but is not
  endorsed or certified by the NVD.

## FIRST EPSS

- API: `https://api.first.org/data/v1/epss`
- The Exploit Prediction Scoring System is a FIRST.org SIG project. EPSS data is
  freely available for use with attribution to FIRST.org. Cite EPSS when
  presenting its scores.

## This project

- Code: MIT (see `LICENSE`).
- Generated/derived data inherits the terms of its upstream sources.

Retrieval dates are recorded per run in `public/data/source_metadata.json`.
