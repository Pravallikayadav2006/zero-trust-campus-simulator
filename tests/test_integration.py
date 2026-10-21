"""End-to-end tests: every predefined scenario through the real pipeline, and quick actions."""
import random

import pytest

from data.scenarios import SCENARIOS, random_request
from models.pipeline import evaluate_access


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: f"{s['id']:02d}-{s['name'][:30]}")
def test_scenario_matches_expected_decision(db, detector, scenario):
    r = evaluate_access(db, detector, scenario["request"], scenario["context"], event_type="scenario_lab")
    assert r["decision"] == scenario["expected"], r["reason"]
    assert db.get_event(r["event_id"])["decision"] == scenario["expected"]


def test_scenarios_cover_required_list():
    assert len(SCENARIOS) >= 10 and sorted(s["id"] for s in SCENARIOS)[:10] == list(range(1, 11))


def test_policy_and_anomaly_are_reported_independently(db, detector):
    by_id = {s["id"]: s for s in SCENARIOS}
    flagged = evaluate_access(db, detector, by_id[5]["request"], by_id[5]["context"], persist=False)
    assert flagged["policy_verdict"] == "PASS" and flagged["anomaly_verdict"] == "ANOMALY"
    denied = evaluate_access(db, detector, by_id[2]["request"], by_id[2]["context"], persist=False)
    assert denied["policy_verdict"] == "FAIL" and denied["anomaly_verdict"] == "NORMAL"


def test_network_path_stops_at_pep_when_denied(db, detector):
    s = SCENARIOS[1]
    denied = evaluate_access(db, detector, s["request"], s["context"], persist=False)
    assert denied["path"]["nodes"][-1] == "pep" and not denied["path"]["reached_target"]
    ok = evaluate_access(db, detector, SCENARIOS[0]["request"], SCENARIOS[0]["context"], persist=False)
    assert ok["path"]["nodes"][-2:] == ["pep", "lms"] and ok["path"]["reached_target"]


@pytest.mark.parametrize("kind", ["normal", "suspicious"])
def test_quick_actions_produce_valid_requests(db, detector, kind):
    for seed in range(15):
        req, ctx, label = random_request(db, kind, random.Random(seed))
        r = evaluate_access(db, detector, req, ctx, event_type="quick_action")
        assert r["policy_checks"][0]["name"] != "request_valid", r["reason"]
        if kind == "suspicious":
            assert r["decision"] in ("FLAG", "DENY")


def test_quick_action_fails_cleanly_without_eligible_users(db):
    for u in db.list_entities("users"):
        db.set_active("users", u["user_id"], False)
    with pytest.raises(ValueError, match="No active"):
        random_request(db, "normal")


def test_dashboard_numbers_come_from_stored_records(seeded_db, detector):
    before = seeded_db.query_events()
    evaluate_access(seeded_db, detector, SCENARIOS[1]["request"], SCENARIOS[1]["context"])
    after = seeded_db.query_events()
    assert len(after) == len(before) + 1
    assert (after.decision == "DENY").sum() == (before.decision == "DENY").sum() + 1
