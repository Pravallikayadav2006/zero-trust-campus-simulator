"""The Zero Trust decision pipeline.

Order of work for one access request
    1. validate the request fields and the behavioural context
    2. resolve user, device and resource            \
    3. verify identity / account status              |  models.policy_engine
    4. verify device status                          |  (ALL of these are mandatory)
    5. role / resource authorisation (RBAC + policy) |
    6. mandatory contextual conditions (time window) /
    7. contextual risk score                          models.risk
    8. anomaly detector result                        models.anomaly
    9. apply the configured risk handling             decide()
   10. build the final decision and plain-English reason
   11. persist the audit event                        database.store

Precedence (highest first) - see decide():
    R1  any mandatory check fails           -> DENY   (risk and anomaly are informational only)
    R2  risk score >= deny threshold         -> DENY
    R3  risk >= flag threshold or anomaly    -> FLAG   (permitted, but flagged for analyst review)
    R4  otherwise                            -> ALLOW

A "normal" anomaly result or a low risk score can never create access: ALLOW is
only reachable when every mandatory check has passed (R1 is evaluated first).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

import config
from models.anomaly import AnomalyDetector, features_from_context
from models.policy_engine import Check, evaluate_policy
from models.risk import score_risk
from utils.validation import normalize_context, validate_request

logger = logging.getLogger(__name__)

RULE_MANDATORY = "R1_mandatory_check_failed"
RULE_RISK_DENY = "R2_risk_above_deny_threshold"
RULE_FLAG = "R3_risk_or_anomaly_flag"
RULE_ALLOW = "R4_all_clear"


def decide(
    mandatory_passed: bool,
    risk_score: float,
    anomaly_detected: bool,
    flag_threshold: float,
    deny_threshold: float,
) -> tuple[str, str]:
    """Pure function holding the precedence rules. Returns (decision, rule_code)."""
    if not mandatory_passed:
        return config.DECISION_DENY, RULE_MANDATORY
    if risk_score >= deny_threshold:
        return config.DECISION_DENY, RULE_RISK_DENY
    if risk_score >= flag_threshold or anomaly_detected:
        return config.DECISION_FLAG, RULE_FLAG
    return config.DECISION_ALLOW, RULE_ALLOW


def _top_factors(risk, n: int = 3) -> str:
    ranked = sorted(risk.factors, key=lambda f: -f["points"])[:n]
    return ", ".join(f"{f['factor'].lower()} (+{f['points']:g})" for f in ranked) or "none"


def build_reason(decision, rule, evaluation, risk, anomaly, thresholds, policy_id) -> str:
    flag_t, deny_t = thresholds["risk_flag_threshold"], thresholds["risk_deny_threshold"]
    if rule == RULE_MANDATORY:
        failures = [c for c in evaluation.checks if c.mandatory and c.status == "fail"]
        text = f"Denied: {failures[0].detail}"
        if len(failures) > 1:
            text += f" ({len(failures) - 1} other mandatory check(s) also failed.)"
        return text + " Risk score and anomaly result cannot override a failed mandatory check."
    if rule == RULE_RISK_DENY:
        return (
            f"Denied by risk policy: every mandatory check passed, but the risk score {risk.score:g} "
            f"is at or above the deny threshold ({deny_t:g}). Main factors: {_top_factors(risk)}."
        )
    if rule == RULE_FLAG:
        parts = []
        if risk.score >= flag_t:
            parts.append(f"risk score {risk.score:g} is at or above the flag threshold ({flag_t:g}); "
                         f"main factors: {_top_factors(risk)}")
        if anomaly.detected:
            sources = []
            if anomaly.method == "isolation_forest" and anomaly.is_anomaly:
                sources.append("the Isolation Forest")
            if anomaly.rule_flag:
                sources.append("the transparent rules")
            why = "; ".join(r["rule"] for r in anomaly.reasons[:2]) or "model score outside the learned normal range"
            parts.append(f"anomaly detected by {' and '.join(sources)} ({why})")
        return (
            f"Allowed but flagged for review under policy {policy_id}: all mandatory checks passed, "
            f"but " + " and ".join(parts) + ". This is suspicious simulated activity, not a confirmed attack."
        )
    return (
        f"Allowed: all mandatory checks passed under policy {policy_id}, the risk score {risk.score:g} is "
        f"{risk.level.lower()} and no anomaly was detected."
    )


def _network_path(user, resource, decision) -> dict:
    role = user["role"] if user else "student"
    device_node = config.ROLE_TO_DEVICE_NODE.get(role, "student_devices")
    target = config.CATEGORY_TO_NODE.get(resource["category"]) if resource else None
    nodes = [device_node, "gateway", "pep"]
    reached = bool(target) and decision != config.DECISION_DENY
    if reached:
        nodes.append(target)
    return {"nodes": nodes, "target": target, "reached_target": reached}


def _event(result: dict, event_type: str, ts: str) -> dict:
    req, risk, anomaly = result["request"], result["risk"], result["anomaly"]
    return {
        "timestamp": ts,
        "user_id": req["user_id"] or None,
        "user_role": result["user"]["role"] if result["user"] else None,
        "device_id": req["device_id"] or None,
        "resource_id": req["resource_id"] or None,
        "request_type": req["request_type"] or None,
        "event_type": event_type,
        "policy_id": result["policy_id"],
        "policy_checks": json.dumps(result["policy_checks"]),
        "risk_score": None if risk is None else risk["score"],
        "risk_level": None if risk is None else risk["level"],
        "risk_factors": None if risk is None else json.dumps(risk["factors"]),
        "anomaly_score": None if anomaly is None else anomaly["score"],
        "anomaly_flag": None if anomaly is None else int(anomaly["detected"]),
        "anomaly_method": None if anomaly is None else anomaly["method"],
        "decision": result["decision"],
        "reason": result["reason"],
        "is_simulated": 1,
        "context": json.dumps(result["context"]) if result["context"] else None,
    }


def evaluate_access(
    db,
    detector: AnomalyDetector,
    request: dict,
    context: dict | None = None,
    now: datetime | None = None,
    event_type: str = "interactive",
    persist: bool = True,
) -> dict:
    """Run the whole pipeline and (optionally) store the audit event.

    Always returns a result dictionary; a malformed request is DENIED and logged
    rather than raising, because every decision must be recorded.
    """
    now = (now or datetime.now()).replace(microsecond=0)
    ts = now.isoformat(sep=" ")
    request = request if isinstance(request, dict) else {}
    req = {
        "user_id": str(request.get("user_id") or "")[:40],
        "device_id": str(request.get("device_id") or "")[:40],
        "resource_id": str(request.get("resource_id") or "")[:40],
        "request_type": str(request.get("request_type") or "")[:20],
    }

    errors = validate_request(request)
    ctx = None
    try:
        ctx = normalize_context(context, now.hour)
    except ValueError as exc:
        errors.append(str(exc))

    thresholds = db.get_thresholds()
    if errors:
        checks = [Check("request_valid", "Request is well-formed", "fail", " ".join(errors)).to_dict()]
        result = {
            "timestamp": ts, "request": req, "context": ctx, "user": None, "device": None, "resource": None,
            "policy_id": None, "policy_checks": checks, "policy_verdict": "FAIL", "risk": None,
            "anomaly": None, "anomaly_verdict": "n/a", "decision": config.DECISION_DENY,
            "decision_rule": RULE_MANDATORY, "thresholds": thresholds,
            "reason": "Denied: the request is malformed. " + " ".join(errors),
            "path": {"nodes": ["student_devices", "gateway", "pep"], "target": None, "reached_target": False},
        }
    else:
        user = db.get_entity("users", req["user_id"])
        device = db.get_entity("devices", req["device_id"])
        resource = db.get_entity("resources", req["resource_id"])
        policies = db.list_entities("policies")
        evaluation = evaluate_policy(
            user, device, resource, req["request_type"], ctx["hour"], policies,
            ids=(req["user_id"], req["device_id"], req["resource_id"]),
        )
        risk = score_risk(ctx, device, resource, now, thresholds["risk_flag_threshold"],
                          thresholds["risk_deny_threshold"])
        compliant = bool(device and device["compliance_status"] == "compliant")
        anomaly = detector.analyze(features_from_context(ctx, compliant))
        decision, rule = decide(
            evaluation.mandatory_passed, risk.score, anomaly.detected,
            thresholds["risk_flag_threshold"], thresholds["risk_deny_threshold"],
        )
        policy_id = None if evaluation.policy is None else evaluation.policy["policy_id"]
        result = {
            "timestamp": ts, "request": req, "context": ctx, "user": user, "device": device,
            "resource": resource, "policy_id": policy_id,
            "policy_checks": [c.to_dict() for c in evaluation.checks],
            "policy_verdict": "PASS" if evaluation.mandatory_passed else "FAIL",
            "risk": risk.to_dict(), "anomaly": {**anomaly.to_dict(), "detected": anomaly.detected},
            "anomaly_verdict": "ANOMALY" if anomaly.detected else "NORMAL",
            "decision": decision, "decision_rule": rule, "thresholds": thresholds,
            "reason": build_reason(decision, rule, evaluation, risk, anomaly, thresholds, policy_id),
            "path": _network_path(user, resource, decision),
        }

    result["event"] = _event(result, event_type, ts)
    result["event_id"] = None
    if persist:
        result["event_id"] = db.add_event(result["event"])
    return result
