"""Central configuration for the Zero Trust Campus Network Simulator.

EDUCATIONAL SIMULATION ONLY. Nothing here connects to a real network.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = BASE_DIR / "runtime"
# The database path can be overridden (used by the tests) with ZT_DB_PATH.
DB_PATH = Path(os.environ.get("ZT_DB_PATH", str(RUNTIME_DIR / "zt_campus.db"))).resolve()

APP_TITLE = "Zero Trust Campus Network Simulator"
APP_SUBTITLE = (
    "An Intelligent Simulation Platform for Identity-Based Access Control "
    "and AI-Powered Network Anomaly Detection"
)
DISCLAIMER = (
    "Educational simulation only. All users, devices, resources and events are fictional "
    "and synthetic. This tool never touches a real network and is not production-ready."
)

RANDOM_SEED = 42

# ---------------------------------------------------------------- vocabularies
ROLES = ("student", "faculty", "admin")
IDENTITY_STATUSES = ("verified", "unverified", "failed")
COMPLIANCE_STATUSES = ("compliant", "noncompliant", "unknown")
DEVICE_TYPES = ("laptop", "smartphone", "tablet", "workstation", "lab_pc")
REQUEST_TYPES = ("read", "write", "manage")
RESOURCE_CATEGORIES = ("Learning", "Library", "Laboratory", "Application", "Administrative")
SENSITIVITY_LEVELS = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_FLAG = "FLAG"
DECISIONS = (DECISION_ALLOW, DECISION_DENY, DECISION_FLAG)

# Event types shown in the audit log filter.
EVENT_TYPES = (
    "seed_simulated",
    "interactive",
    "scenario_lab",
    "quick_action",
)

# ------------------------------------------------------------ policy / context
BUSINESS_HOURS = (8, 18)      # policies marked "business hours only" need 8 <= hour < 18
UNUSUAL_HOURS = (6, 22)       # hour < 6 or hour >= 22 counts as an unusual access time
WINDOW_MINUTES = 10           # length of the "requests per window" time window
WINDOWS_PER_HOUR = 60 // WINDOW_MINUTES

# Editable at run time on the Policy Engine page (stored in the settings table).
DEFAULT_SETTINGS = {
    "risk_flag_threshold": 35.0,   # risk >= this (or anomaly detected) -> FLAG
    "risk_deny_threshold": 70.0,   # risk >= this -> DENY
}

# Baseline behaviour used when the user does not override the context.
DEFAULT_CONTEXT = {
    "hour": None,                  # None -> taken from the request timestamp
    "failed_auth_count": 0,
    "requests_per_window": 3,
    "access_frequency": 18.0,      # accesses per hour, 24 h average
    "distinct_resources": 1,
    "failed_request_ratio": 0.0,
}

# ------------------------------------------------------------ network topology
CATEGORY_TO_NODE = {
    "Learning": "lms",
    "Library": "library",
    "Laboratory": "labs",
    "Application": "app_server",
    "Administrative": "admin_server",
}
ROLE_TO_DEVICE_NODE = {
    "student": "student_devices",
    "faculty": "faculty_devices",
    "admin": "admin_devices",
}
