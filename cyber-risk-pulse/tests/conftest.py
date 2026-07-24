import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def kev_payload():
    return json.loads((FIXTURES / "cisa_kev_sample.json").read_text("utf-8"))


@pytest.fixture
def nvd_payload():
    return json.loads((FIXTURES / "nvd_sample.json").read_text("utf-8"))


@pytest.fixture
def epss_payload():
    return json.loads((FIXTURES / "epss_sample.json").read_text("utf-8"))
