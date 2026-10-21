"""Risk scoring tests."""
from datetime import datetime

import config
from models.risk import risk_level, score_risk

NOW = datetime(2026, 3, 10, 12, 0, 0)
BASE = dict(config.DEFAULT_CONTEXT, hour=12)
DEVICE = {"last_verified": "2026-03-01"}
LMS = {"sensitivity": 1}


def test_risk_is_deterministic():
    ctx = dict(BASE, failed_auth_count=3, requests_per_window=12)
    a = score_risk(ctx, DEVICE, LMS, NOW)
    b = score_risk(dict(ctx), dict(DEVICE), dict(LMS), NOW)
    assert a.score == b.score and a.factors == b.factors


def test_baseline_context_has_zero_risk():
    r = score_risk(BASE, DEVICE, LMS, NOW)
    assert r.score == 0 and r.level == "Low" and r.factors == []


def test_failed_auth_points_and_cap():
    assert score_risk(dict(BASE, failed_auth_count=2), DEVICE, LMS, NOW).score == 12
    assert score_risk(dict(BASE, failed_auth_count=20), DEVICE, LMS, NOW).score == 30


def test_unusual_hour_adds_fifteen():
    r = score_risk(dict(BASE, hour=3), DEVICE, LMS, NOW)
    assert r.score == 15 and r.factors[0]["factor"] == "Unusual access time"


def test_resource_sensitivity_and_stale_device():
    r = score_risk(BASE, {"last_verified": "2025-01-01"}, {"sensitivity": 4}, NOW)
    names = {f["factor"] for f in r.factors}
    assert names == {"Resource sensitivity", "Stale device verification"}
    assert r.score == 19


def test_invalid_verification_date_counts_as_stale():
    r = score_risk(BASE, {"last_verified": "not-a-date"}, LMS, NOW)
    assert r.score == 10


def test_score_capped_at_100():
    ctx = dict(BASE, hour=2, failed_auth_count=9, requests_per_window=200, distinct_resources=30,
               failed_request_ratio=1.0)
    assert score_risk(ctx, {"last_verified": None}, {"sensitivity": 4}, NOW).score == 100


def test_risk_levels_follow_thresholds():
    assert risk_level(10, 35, 70) == "Low"
    assert risk_level(35, 35, 70) == "Medium"
    assert risk_level(70, 35, 70) == "High"


def test_factors_explain_the_score():
    r = score_risk(dict(BASE, failed_auth_count=2, hour=2), DEVICE, LMS, NOW)
    assert round(sum(f["points"] for f in r.factors), 1) == r.score
