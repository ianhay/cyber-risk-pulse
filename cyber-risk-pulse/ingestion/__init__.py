"""Cyber Risk Pulse data ingestion package.

Downloads, validates, joins and prioritises public vulnerability data
(CISA KEV, NVD CVE API 2.0, FIRST EPSS) into compact, dashboard-ready
static files. All upstream formats are isolated behind source adapters;
canonical joined data lives in :mod:`ingestion.models`.
"""

__version__ = "0.1.0"
