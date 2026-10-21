"""Zero Trust policy engine: mandatory checks only.

Every check here is MANDATORY. If any check fails the request is denied, no
matter what the risk score or the anomaly detector says. Network location is
never an input: being "inside the campus" earns no trust.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

import config
from utils.validation import split_csv


@dataclass
class Check:
    name: str
    label: str
    status: str            # "pass" | "fail" | "skipped"
    detail: str
    mandatory: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PolicyEvaluation:
    checks: list = field(default_factory=list)
    policy: dict | None = None
    mandatory_passed: bool = False

    @property
    def first_failure(self) -> Check | None:
        return next((c for c in self.checks if c.mandatory and c.status == "fail"), None)

    def to_dict(self) -> dict:
        return {
            "checks": [c.to_dict() for c in self.checks],
            "policy_id": None if self.policy is None else self.policy["policy_id"],
            "mandatory_passed": self.mandatory_passed,
        }


def select_policy(role: str, resource: dict, request_type: str, policies: list[dict]):
    """Pick the policy that applies. Returns (policy|None, grants: bool, explanation)."""
    candidates = [
        p for p in policies
        if p.get("enabled") and p["role"] == role and p["resource_category"] in (resource["category"], "*")
    ]
    # Specific category beats wildcard; policy_id breaks ties so results are deterministic.
    candidates.sort(key=lambda p: (p["resource_category"] == "*", p["policy_id"]))
    for p in candidates:
        if resource["sensitivity"] <= p["max_sensitivity"] and request_type in split_csv(p["request_types"]):
            return p, True, f"Policy {p['policy_id']} ({p['name']}) permits this."
    if candidates:
        p = candidates[0]
        if resource["sensitivity"] > p["max_sensitivity"]:
            why = (
                f"resource sensitivity {resource['sensitivity']} "
                f"({config.SENSITIVITY_LEVELS.get(resource['sensitivity'])}) is above this policy's "
                f"maximum of {p['max_sensitivity']}"
            )
        else:
            why = f"request type '{request_type}' is not allowed (allowed: {', '.join(split_csv(p['request_types']))})"
        return p, False, f"Policy {p['policy_id']} applies but {why}."
    return None, False, (
        f"No enabled policy grants role '{role}' access to {resource['category']} resources (default deny)."
    )


def evaluate_policy(
    user: dict | None,
    device: dict | None,
    resource: dict | None,
    request_type: str,
    hour: int,
    policies: list[dict],
    ids: tuple[str, str, str] = ("?", "?", "?"),
) -> PolicyEvaluation:
    uid, did, rid = ids
    checks: list[Check] = []

    def add(name, label, status, detail):
        checks.append(Check(name, label, status, detail))

    def ok(name, label, passed, detail_pass, detail_fail):
        add(name, label, "pass" if passed else "fail", detail_pass if passed else detail_fail)

    # 1-3. resolve the three parties of the request
    ok("user_resolved", "User is registered", user is not None,
       f"User '{uid}' found.", f"User '{uid}' is not registered.")
    ok("device_resolved", "Device is registered", device is not None,
       f"Device '{did}' found.", f"Device '{did}' is not registered.")
    ok("resource_resolved", "Resource exists", resource is not None,
       f"Resource '{rid}' found.", f"Resource '{rid}' does not exist.")

    skip = "Not evaluated because an earlier lookup failed."

    # 4-5. identity
    if user is not None:
        ok("account_active", "Account is active", bool(user["active"]),
           "The account is active.", "The account is inactive (deactivated).")
        ok("identity_verified", "Identity is verified", user["identity_status"] == "verified",
           "Identity verification succeeded.",
           f"Identity verification status is '{user['identity_status']}', not 'verified'.")
    else:
        add("account_active", "Account is active", "skipped", skip)
        add("identity_verified", "Identity is verified", "skipped", skip)

    # select the governing policy (needed for device and time requirements)
    policy, grants, policy_note = (None, False, skip)
    if user is not None and resource is not None:
        policy, grants, policy_note = select_policy(user["role"], resource, request_type, policies)

    # 6-8. device
    if device is not None:
        ok("device_active", "Device is active", bool(device["active"]),
           "The device is active.", "The device is deactivated.")
        require = True if policy is None else bool(policy["require_compliant_device"])
        if not require:
            add("device_compliance", "Device is compliant", "pass",
                f"Compliance not required by policy {policy['policy_id']} (status: {device['compliance_status']}).")
        else:
            ok("device_compliance", "Device is compliant", device["compliance_status"] == "compliant",
               "The device is compliant.",
               f"Device compliance status is '{device['compliance_status']}', but a compliant device is required.")
        if user is not None:
            ok("device_binding", "Device belongs to the user", device["owner_id"] == user["user_id"],
               "The device is registered to this user.",
               f"The device is registered to '{device['owner_id']}', not to '{user['user_id']}'.")
        else:
            add("device_binding", "Device belongs to the user", "skipped", skip)
    else:
        for name, label in (("device_active", "Device is active"),
                            ("device_compliance", "Device is compliant"),
                            ("device_binding", "Device belongs to the user")):
            add(name, label, "skipped", skip)

    # 9-11. authorisation
    if resource is not None:
        ok("resource_active", "Resource is available", bool(resource["active"]),
           "The resource is active.", "The resource is deactivated.")
    else:
        add("resource_active", "Resource is available", "skipped", skip)

    if user is not None and resource is not None:
        roles = split_csv(resource["allowed_roles"])
        ok("role_authorized", "Role is allowed on the resource", user["role"] in roles,
           f"Role '{user['role']}' is in the resource's allowed roles ({', '.join(roles)}).",
           f"Role '{user['role']}' is not in the resource's allowed roles ({', '.join(roles)}).")
        ok("policy_match", "An access policy grants this request", grants, policy_note, policy_note)
    else:
        add("role_authorized", "Role is allowed on the resource", "skipped", skip)
        add("policy_match", "An access policy grants this request", "skipped", skip)

    # 12. mandatory contextual condition
    if policy is not None:
        if policy["business_hours_only"]:
            start, end = config.BUSINESS_HOURS
            ok("time_window", "Request is inside the allowed time window", start <= hour < end,
               f"Hour {hour:02d}:00 is inside business hours ({start:02d}:00-{end:02d}:00).",
               f"Policy {policy['policy_id']} allows access only during business hours "
               f"({start:02d}:00-{end:02d}:00); the request is at {hour:02d}:00.")
        else:
            add("time_window", "Request is inside the allowed time window", "pass",
                f"Policy {policy['policy_id']} has no time restriction.")
    else:
        add("time_window", "Request is inside the allowed time window", "skipped", skip)

    passed = all(c.status == "pass" for c in checks if c.mandatory)
    return PolicyEvaluation(checks=checks, policy=policy, mandatory_passed=passed)


def build_policy_matrix(resources: list[dict], policies: list[dict]) -> list[dict]:
    """Role x resource table: what each role could do under ideal conditions."""
    rows = []
    for role in config.ROLES:
        user = {"user_id": "U-IDEAL", "role": role, "identity_status": "verified", "active": 1}
        device = {"device_id": "D-IDEAL", "owner_id": "U-IDEAL", "compliance_status": "compliant", "active": 1}
        for res in resources:
            if not res["active"]:
                continue
            permitted, applied = [], None
            for rt in config.REQUEST_TYPES:
                ev = evaluate_policy(user, device, res, rt, config.BUSINESS_HOURS[0], policies)
                if ev.mandatory_passed:
                    permitted.append(rt)
                    applied = applied or ev.policy
            _, _, note = select_policy(role, res, "read", policies)
            conditions = ["verified identity", "active account", "device registered to user"]
            if applied is not None:
                if applied["require_compliant_device"]:
                    conditions.append("compliant device")
                if applied["business_hours_only"]:
                    conditions.append("business hours only")
            rows.append({
                "Role": role,
                "Resource": f"{res['resource_id']} - {res['name']}",
                "Sensitivity": config.SENSITIVITY_LEVELS.get(res["sensitivity"], res["sensitivity"]),
                "Policy": applied["policy_id"] if applied else "-",
                "Required conditions": ", ".join(conditions) if applied else "n/a",
                "Result (ideal conditions)": f"ALLOW ({', '.join(permitted)})" if permitted else "DENY",
                "Note": "" if permitted else note,
            })
    return rows
