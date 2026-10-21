"""Policy engine tests: mandatory checks only (no risk, no anomaly)."""
from datetime import datetime

from tests.conftest import req
from models.pipeline import decide, evaluate_access

NOON = datetime(2026, 3, 10, 12, 0, 0)
CTX = {"hour": 12}


def run(db, detector, request, ctx=CTX, persist=False):
    return evaluate_access(db, detector, request, ctx, now=NOON, persist=persist)


def failed(result):
    return {c["name"] for c in result["policy_checks"] if c["status"] == "fail"}


def test_student_allowed_learning_resource(db, detector):
    r = run(db, detector, req())
    assert r["decision"] == "ALLOW" and r["policy_verdict"] == "PASS"
    assert r["policy_id"] == "P-01"


def test_student_denied_admin_only_resource(db, detector):
    r = run(db, detector, req(resource="R-ADM", rtype="manage"))
    assert r["decision"] == "DENY"
    assert "role_authorized" in failed(r)


def test_invalid_identity_verification_denied(db, detector):
    r = run(db, detector, req(user="U-S04", device="D-S04L"))   # identity_status == failed
    assert r["decision"] == "DENY" and "identity_verified" in failed(r)


def test_unverified_identity_denied(db, detector):
    db.update_entity("users", "U-S01", {"identity_status": "unverified"})
    r = run(db, detector, req())
    assert r["decision"] == "DENY" and "identity_verified" in failed(r)


def test_inactive_user_denied(db, detector):
    r = run(db, detector, req(user="U-S05", device="D-S05T"))
    assert r["decision"] == "DENY" and "account_active" in failed(r)


def test_noncompliant_device_denied_for_protected_resource(db, detector):
    r = run(db, detector, req(user="U-S03", device="D-S03P"))
    assert r["decision"] == "DENY" and "device_compliance" in failed(r)


def test_device_must_belong_to_user(db, detector):
    r = run(db, detector, req(user="U-S01", device="D-S02L"))
    assert r["decision"] == "DENY" and "device_binding" in failed(r)


def test_missing_user_and_device_denied(db, detector):
    r = run(db, detector, req(user="U-NOPE", device="D-NOPE"))
    assert r["decision"] == "DENY"
    assert {"user_resolved", "device_resolved"} <= failed(r)
    assert r["user"] is None and r["device"] is None


def test_unknown_resource_denied(db, detector):
    r = run(db, detector, req(resource="R-NOPE"))
    assert r["decision"] == "DENY" and "resource_resolved" in failed(r)


def test_malformed_request_denied_and_recorded(db, detector):
    r = evaluate_access(db, detector, {"user_id": "bad id!", "device_id": "", "resource_id": "R-LMS",
                                       "request_type": "delete"}, now=NOON)
    assert r["decision"] == "DENY" and r["event_id"] is not None
    assert db.count_events() == 1


def test_non_dict_request_denied(db, detector):
    assert run(db, detector, None)["decision"] == "DENY"


def test_invalid_context_denied(db, detector):
    r = run(db, detector, req(), {"hour": 99})
    assert r["decision"] == "DENY" and "request_valid" in failed(r)


def test_unauthorised_request_type_denied(db, detector):
    # P-02 lets students only READ library content.
    r = run(db, detector, req(resource="R-LIB", rtype="write"))
    assert r["decision"] == "DENY" and "policy_match" in failed(r)


def test_business_hours_policy_blocks_lab_at_night(db, detector):
    r = run(db, detector, req(user="U-S02", device="D-S02L", resource="R-LAB"), {"hour": 21})
    assert r["decision"] == "DENY" and "time_window" in failed(r)
    assert run(db, detector, req(user="U-S02", device="D-S02L", resource="R-LAB"), {"hour": 10})["decision"] == "ALLOW"


def test_default_deny_when_no_policy(db, detector):
    db.set_active("policies", "P-01", False)
    r = run(db, detector, req())
    assert r["decision"] == "DENY" and "policy_match" in failed(r)


# ----------------------------------------------- policy / entity edits affect later decisions
def test_policy_change_affects_subsequent_decisions(db, detector):
    assert run(db, detector, req())["decision"] == "ALLOW"
    db.update_entity("policies", "P-01", {"request_types": "write"})      # remove 'read'
    assert run(db, detector, req())["decision"] == "DENY"
    db.update_entity("policies", "P-01", {"request_types": "read,write"})
    assert run(db, detector, req())["decision"] == "ALLOW"


def test_policy_compliance_requirement_can_be_relaxed(db, detector):
    request = req(user="U-S03", device="D-S03P")
    assert run(db, detector, request)["decision"] == "DENY"
    db.update_entity("policies", "P-01", {"require_compliant_device": 0})
    assert "device_compliance" not in failed(run(db, detector, request))


def test_role_change_affects_subsequent_decisions(db, detector):
    request = req(user="U-S01", device="D-S01L", resource="R-GRD", rtype="write")
    assert run(db, detector, request)["decision"] == "DENY"                # student: no policy
    db.update_entity("users", "U-S01", {"role": "faculty"})
    assert run(db, detector, request)["decision"] == "ALLOW"               # faculty: P-07


def test_device_compliance_change_affects_subsequent_decisions(db, detector):
    request = req(user="U-S03", device="D-S03P")
    assert run(db, detector, request)["decision"] == "DENY"
    db.update_entity("devices", "D-S03P", {"compliance_status": "compliant"})
    assert run(db, detector, request)["decision"] == "ALLOW"


def test_decisions_are_deterministic(db, detector):
    a = run(db, detector, req())
    b = run(db, detector, req())
    for key in ("decision", "reason", "policy_checks", "risk", "decision_rule"):
        assert a[key] == b[key]


# ------------------------------------------------------------------ precedence rules
def test_decide_precedence_table():
    # R1: a failed mandatory check wins over every other signal
    assert decide(False, 0.0, False, 35, 70) == ("DENY", "R1_mandatory_check_failed")
    # R2 / R3 / R4
    assert decide(True, 90, False, 35, 70)[0] == "DENY"
    assert decide(True, 40, False, 35, 70)[0] == "FLAG"
    assert decide(True, 0, True, 35, 70)[0] == "FLAG"
    assert decide(True, 5, False, 35, 70)[0] == "ALLOW"


def test_normal_anomaly_and_low_risk_never_override_failed_mandatory_check(db, detector):
    r = run(db, detector, req(resource="R-ADM", rtype="manage"))
    assert r["risk"]["level"] == "Low" and r["anomaly_verdict"] == "NORMAL"
    assert r["decision"] == "DENY"


def test_anomaly_flags_but_does_not_deny_a_permitted_request(db, detector):
    r = run(db, detector, req(), {"hour": 12, "failed_auth_count": 6, "failed_request_ratio": 0.5,
                                  "requests_per_window": 8})
    assert r["policy_verdict"] == "PASS" and r["anomaly_verdict"] == "ANOMALY"
    assert r["decision"] == "FLAG"


def test_threshold_change_turns_flag_into_deny(db, detector):
    ctx = {"hour": 12, "failed_auth_count": 6, "failed_request_ratio": 0.5, "requests_per_window": 8}
    assert run(db, detector, req(), ctx)["decision"] == "FLAG"
    db.set_setting("risk_deny_threshold", 40)
    assert run(db, detector, req(), ctx)["decision"] == "DENY"
