"""Shared fixtures. Every test uses its own temporary SQLite file, never the real runtime DB."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Point the app at a throw-away database BEFORE config is imported, so no test can touch runtime/zt_campus.db.
os.environ["ZT_DB_PATH"] = str(Path(tempfile.mkdtemp(prefix="zt_pytest_")) / "pytest_app.db")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from data.seed import default_entities, ensure_seeded  # noqa: E402
from database.store import Database  # noqa: E402
from models.anomaly import AnomalyDetector  # noqa: E402


@pytest.fixture(scope="session")
def detector():
    """One trained detector for the whole test run (training is deterministic, ~1 s)."""
    return AnomalyDetector().fit()


@pytest.fixture
def db(tmp_path):
    """Database with the fictional demo entities and policies but NO events."""
    database = Database(tmp_path / "test.db")
    e = default_entities()
    database.seed_entities(e["users"], e["devices"], e["resources"], e["policies"])
    return database


@pytest.fixture
def seeded_db(tmp_path, detector):
    """Database with entities AND the initial synthetic audit events."""
    database = Database(tmp_path / "seeded.db")
    ensure_seeded(database, detector)
    return database


def req(user="U-S01", device="D-S01L", resource="R-LMS", rtype="read"):
    return {"user_id": user, "device_id": device, "resource_id": resource, "request_type": rtype}
