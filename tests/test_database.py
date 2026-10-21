"""Persistence, audit records, seeding idempotency and CSV export."""
import json
import sqlite3

import pytest

from tests.conftest import req
from data.seed import ensure_seeded
from database.store import Database, DuplicateIdError
from models.pipeline import evaluate_access
from utils.export import events_to_csv, sanitize_cell, validate_csv
from utils.validation import validate_device, validate_policy, validate_resource, validate_user


def test_schema_created(tmp_path):
    Database(tmp_path / "x.db")
    with sqlite3.connect(tmp_path / "x.db") as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "devices", "resources", "policies", "settings", "events"} <= tables


def test_audit_record_created_with_all_fields(db, detector):
    r = evaluate_access(db, detector, req(), {"hour": 12})
    row = db.get_event(r["event_id"])
    assert row["user_id"] == "U-S01" and row["user_role"] == "student" and row["device_id"] == "D-S01L"
    assert row["resource_id"] == "R-LMS" and row["decision"] == "ALLOW" and row["is_simulated"] == 1
    assert row["reason"] and row["timestamp"] and row["event_type"] == "interactive"
    assert row["risk_score"] is not None and row["anomaly_method"] is not None
    checks = json.loads(row["policy_checks"])
    assert all({"name", "status", "detail"} <= set(c) for c in checks)


def test_every_decision_is_recorded_including_denials(db, detector):
    for request in (req(), req(resource="R-ADM", rtype="manage"), req(user="U-NOPE")):
        evaluate_access(db, detector, request, {"hour": 12})
    assert db.count_events() == 3
    assert set(db.query_events()["decision"]) == {"ALLOW", "DENY"}


def test_persist_false_writes_nothing(db, detector):
    evaluate_access(db, detector, req(), persist=False)
    assert db.count_events() == 0


def test_events_persist_across_restart(tmp_path, detector):
    path = tmp_path / "persist.db"
    first = Database(path)
    e_db = first
    from data.seed import default_entities
    e = default_entities()
    e_db.seed_entities(e["users"], e["devices"], e["resources"], e["policies"])
    evaluate_access(e_db, detector, req(), {"hour": 12})
    del first, e_db
    reopened = Database(path)                       # simulates an application restart
    assert reopened.count_events() == 1 and len(reopened.list_entities("users")) == 12


def test_seeding_is_idempotent(tmp_path, detector):
    d = Database(tmp_path / "s.db")
    assert ensure_seeded(d, detector) is True
    n_events, n_users = d.count_events(), len(d.list_entities("users"))
    assert ensure_seeded(d, detector) is False       # a Streamlit rerun / restart
    assert d.count_events() == n_events and len(d.list_entities("users")) == n_users


def test_seed_data_meets_requirements(seeded_db):
    assert len(seeded_db.list_entities("users")) >= 12 and len(seeded_db.list_entities("devices")) >= 12
    assert len(seeded_db.list_entities("resources")) >= 6 and len(seeded_db.list_entities("policies")) >= 5
    events = seeded_db.query_events()
    assert len(events) >= 100 and (events["is_simulated"] == 1).all()
    assert {"ALLOW", "DENY", "FLAG"} <= set(events["decision"])
    assert events["user_id"].nunique() < len(events)         # requests != unique users


def test_edits_survive_reseed(seeded_db, detector):
    seeded_db.update_entity("users", "U-S01", {"role": "faculty"})
    ensure_seeded(seeded_db, detector)
    assert seeded_db.get_entity("users", "U-S01")["role"] == "faculty"


def test_duplicate_id_rejected(db):
    with pytest.raises(DuplicateIdError):
        db.insert_entity("users", {"user_id": "U-S01", "display_name": "Dup", "role": "student",
                                   "identity_status": "verified", "active": 1})


def test_foreign_key_enforced(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_entity("devices", {"device_id": "D-X1", "device_type": "laptop", "owner_id": "U-NOPE",
                                     "compliance_status": "compliant", "last_verified": "2026-01-01", "active": 1})


def test_unknown_table_and_column_rejected(db):
    with pytest.raises(ValueError):
        db.list_entities("users; DROP TABLE users")
    with pytest.raises(ValueError):
        db.update_entity("users", "U-S01", {"role = 'admin' --": "x"})
    with pytest.raises(ValueError):
        db.query_events(sort_by="timestamp; DROP TABLE events")


def test_sql_injection_in_search_is_inert(seeded_db):
    out = seeded_db.query_events(search="' OR 1=1 --")
    assert len(out) == 0 and seeded_db.count_events() > 0


def test_filters_and_sorting(seeded_db):
    only_deny = seeded_db.query_events(decisions=["DENY"])
    assert len(only_deny) > 0 and set(only_deny["decision"]) == {"DENY"}
    students = seeded_db.query_events(roles=["student"], resources=["R-LMS"])
    assert set(students["user_role"]) <= {"student"} and set(students["resource_id"]) <= {"R-LMS"}
    asc = seeded_db.query_events(sort_by="risk_score", ascending=True)["risk_score"].dropna().tolist()
    assert asc == sorted(asc)
    ts = seeded_db.query_events()["timestamp"].tolist()
    assert seeded_db.query_events(start=ts[len(ts) // 2])["timestamp"].min() >= ts[len(ts) // 2]


def test_clear_events_keeps_entities(seeded_db):
    assert seeded_db.clear_events() > 0
    assert seeded_db.count_events() == 0 and len(seeded_db.list_entities("users")) == 12


def test_thresholds_default_and_update(db):
    assert db.get_thresholds() == {"risk_flag_threshold": 35.0, "risk_deny_threshold": 70.0}
    db.set_setting("risk_flag_threshold", 20)
    assert db.get_thresholds()["risk_flag_threshold"] == 20.0
    db.set_setting("risk_deny_threshold", "garbage")
    assert db.get_thresholds()["risk_deny_threshold"] == 70.0


# ---------------------------------------------------------------------------- CSV export
def test_csv_export_matches_filtered_records(seeded_db):
    df = seeded_db.query_events(decisions=["DENY"])
    text = events_to_csv(df)
    assert validate_csv(text, len(df)) == []
    assert text.count("DENY") >= len(df)


def test_csv_validation_detects_problems(seeded_db):
    df = seeded_db.query_events(limit=5)
    text = events_to_csv(df)
    assert validate_csv(text, 4) != []
    assert validate_csv("", 0) == ["The CSV is empty."]
    assert validate_csv("a,b\n1,2\n", 1) != []


def test_csv_neutralises_formula_injection(seeded_db):
    df = seeded_db.query_events(limit=2).copy()
    df.loc[df.index[0], "reason"] = "=HYPERLINK(\"http://evil\")"
    text = events_to_csv(df)
    assert "'=HYPERLINK" in text and sanitize_cell("-5") == "'-5" and sanitize_cell(-5) == -5


def test_csv_export_rejects_missing_columns(seeded_db):
    with pytest.raises(ValueError):
        events_to_csv(seeded_db.query_events(limit=2).drop(columns=["reason"]))


# ------------------------------------------------------------------ form validation
def test_validators_reject_bad_input(db):
    ids = [u["user_id"] for u in db.list_entities("users")]
    good = {"user_id": "U-N01", "display_name": "New Person", "role": "student", "identity_status": "verified"}
    assert validate_user(good, ids) == []
    assert validate_user(dict(good, user_id="U-S01"), ids)                       # duplicate
    assert validate_user(dict(good, role="root"), ids)                           # bad role
    assert validate_user(dict(good, display_name="<script>"), ids)               # bad characters
    dev = {"device_id": "D-N01", "device_type": "laptop", "owner_id": "U-S01", "compliance_status": "compliant",
           "last_verified": "2026-01-01"}
    assert validate_device(dev, [], ids) == []
    assert validate_device(dict(dev, owner_id="U-NOPE"), [], ids)                # invalid reference
    assert validate_device(dict(dev, last_verified="2999-01-01"), [], ids)       # future date
    res = {"resource_id": "R-N01", "name": "New", "category": "Learning", "sensitivity": 1, "allowed_roles": "student"}
    assert validate_resource(res, []) == [] and validate_resource(dict(res, allowed_roles=""), [])
    pol = {"policy_id": "P-99", "name": "Test", "role": "student", "resource_category": "*", "max_sensitivity": 2,
           "request_types": "read"}
    assert validate_policy(pol, []) == [] and validate_policy(dict(pol, request_types="delete"), [])
