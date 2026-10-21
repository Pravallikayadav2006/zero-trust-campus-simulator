"""Predefined scenarios for the Scenario Lab and random request generators for quick actions.

All identifiers refer to the fictional demo entities created in data/seed.py.
Each scenario states the decision the default configuration is EXPECTED to produce,
so the Scenario Lab can show expected vs. actual (and catch accidental policy edits).
"""
from __future__ import annotations

import random

import config

SCENARIOS = [
    {
        "id": 1, "name": "Normal student access",
        "description": "A verified student on a compliant laptop reads the learning platform during the day.",
        "request": {"user_id": "U-S01", "device_id": "D-S01L", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 11}, "expected": config.DECISION_ALLOW,
    },
    {
        "id": 2, "name": "Student attempts restricted administrative access",
        "description": "A student asks to manage the administrative records server (least privilege).",
        "request": {"user_id": "U-S01", "device_id": "D-S01L", "resource_id": "R-ADM", "request_type": "manage"},
        "context": {"hour": 11}, "expected": config.DECISION_DENY,
    },
    {
        "id": 3, "name": "Invalid identity verification",
        "description": "A user whose identity verification failed requests the learning platform.",
        "request": {"user_id": "U-S04", "device_id": "D-S04L", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 11}, "expected": config.DECISION_DENY,
    },
    {
        "id": 4, "name": "Noncompliant device",
        "description": "A verified student uses a device that is marked noncompliant.",
        "request": {"user_id": "U-S03", "device_id": "D-S03P", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 11}, "expected": config.DECISION_DENY,
    },
    {
        "id": 5, "name": "Repeated failed authentication",
        "description": "Valid student and device, but six failed sign-in attempts and many failed requests.",
        "request": {"user_id": "U-S02", "device_id": "D-S02L", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 14, "failed_auth_count": 6, "failed_request_ratio": 0.5, "requests_per_window": 8},
        "expected": config.DECISION_FLAG,
    },
    {
        "id": 6, "name": "Unusual request frequency",
        "description": "A student who normally makes a few requests suddenly sends 45 in one 10-minute window.",
        "request": {"user_id": "U-S06", "device_id": "D-S06L", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 15, "requests_per_window": 45, "access_frequency": 15.0, "failed_request_ratio": 0.1},
        "expected": config.DECISION_FLAG,
    },
    {
        "id": 7, "name": "Access to an unexpected set of resources",
        "description": "A faculty member touches nine different resources within one window.",
        "request": {"user_id": "U-F01", "device_id": "D-F01L", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 13, "distinct_resources": 9, "requests_per_window": 14},
        "expected": config.DECISION_FLAG,
    },
    {
        "id": 8, "name": "Unusual access time",
        "description": "A valid student is very active at 03:00, far outside normal hours.",
        "request": {"user_id": "U-S01", "device_id": "D-S01L", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 3, "requests_per_window": 12}, "expected": config.DECISION_FLAG,
    },
    {
        "id": 9, "name": "Faculty accesses a permitted academic resource",
        "description": "A verified faculty member updates the gradebook from a compliant laptop.",
        "request": {"user_id": "U-F01", "device_id": "D-F01L", "resource_id": "R-GRD", "request_type": "write"},
        "context": {"hour": 10}, "expected": config.DECISION_ALLOW,
    },
    {
        "id": 10, "name": "Administrator accesses a permitted administrative resource",
        "description": "A verified administrator manages the administrative records during business hours.",
        "request": {"user_id": "U-A01", "device_id": "D-A01W", "resource_id": "R-ADM", "request_type": "manage"},
        "context": {"hour": 10}, "expected": config.DECISION_ALLOW,
    },
    {
        "id": 11, "name": "Inactive account (extra)",
        "description": "A deactivated student account tries to read the learning platform.",
        "request": {"user_id": "U-S05", "device_id": "D-S05T", "resource_id": "R-LMS", "request_type": "read"},
        "context": {"hour": 11}, "expected": config.DECISION_DENY,
    },
    {
        "id": 12, "name": "Lab access outside business hours (extra)",
        "description": "A student requests the computer lab at 21:00; the lab policy allows business hours only.",
        "request": {"user_id": "U-S02", "device_id": "D-S02L", "resource_id": "R-LAB", "request_type": "read"},
        "context": {"hour": 21}, "expected": config.DECISION_DENY,
    },
]


def get_scenario(scenario_id: int) -> dict:
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    raise KeyError(f"Unknown scenario id {scenario_id}")


# ------------------------------------------------------- random quick actions
SUSPICIOUS_PROFILES = {
    "burst": ("Request burst", {"requests_per_window": (25, 80), "failed_request_ratio": (0.05, 0.2)}),
    "brute_force": ("Repeated failed authentication",
                    {"failed_auth_count": (4, 10), "failed_request_ratio": (0.4, 0.9), "requests_per_window": (5, 14)}),
    "odd_hours": ("Unusual access time", {"hour": (1, 4), "requests_per_window": (9, 20)}),
    "resource_sweep": ("Resource sweep", {"distinct_resources": (6, 12), "requests_per_window": (8, 20)}),
}


def _eligible_pairs(db):
    users = {u["user_id"]: u for u in db.list_entities("users", active_only=True)
             if u["identity_status"] == "verified"}
    return [(users[d["owner_id"]], d) for d in db.list_entities("devices", active_only=True)
            if d["owner_id"] in users and d["compliance_status"] == "compliant"]


def random_request(db, kind: str, rng: random.Random | None = None) -> tuple[dict, dict, str]:
    """Return (request, context, label) for a random 'normal' or 'suspicious' simulation."""
    rng = rng or random.Random()
    pairs = _eligible_pairs(db)
    if not pairs:
        raise ValueError("No active, verified user with an active compliant device is registered.")
    user, device = rng.choice(pairs)
    resources = [r for r in db.list_entities("resources", active_only=True)
                 if user["role"] in r["allowed_roles"].split(",")]
    if not resources:
        raise ValueError(f"No active resource is open to the role '{user['role']}'.")
    if kind == "normal":
        res = rng.choice(resources)
        ctx = {"hour": rng.randint(9, 16), "requests_per_window": rng.randint(1, 5),
               "access_frequency": round(rng.uniform(12, 25), 1), "distinct_resources": rng.randint(1, 2)}
        req = {"user_id": user["user_id"], "device_id": device["device_id"], "resource_id": res["resource_id"],
               "request_type": "read"}
        return req, ctx, "Normal activity"
    if kind == "suspicious":
        key = rng.choice(sorted(SUSPICIOUS_PROFILES))
        label, ranges = SUSPICIOUS_PROFILES[key]
        ctx = {}
        for name, (lo, hi) in ranges.items():
            ctx[name] = round(rng.uniform(lo, hi), 2) if isinstance(lo, float) else rng.randint(lo, hi)
        res = rng.choice(resources)
        req = {"user_id": user["user_id"], "device_id": device["device_id"], "resource_id": res["resource_id"],
               "request_type": "read"}
        return req, ctx, label
    raise ValueError("kind must be 'normal' or 'suspicious'.")
