"""UI smoke tests using Streamlit's official AppTest runner.

These need the real `streamlit` package; they are skipped automatically when it is not installed.
Each page script is executed headlessly against a temporary database and must finish without an exception.
"""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
pytest.importorskip("plotly")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PAGES = ["page_overview", "page_network", "page_policy", "page_anomaly", "page_scenarios", "page_logs",
         "page_entities"]


def test_entry_point_runs():
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120).run()
    assert not at.exception


@pytest.mark.parametrize("page", PAGES)
def test_page_runs_without_exception(page):
    at = AppTest.from_file(str(ROOT / "pages" / f"{page}.py"), default_timeout=120).run()
    assert not at.exception, [e.value for e in at.exception]
