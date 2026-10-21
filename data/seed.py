"""Fictional demo campus + initial synthetic audit events.

Everything here is invented. Seeding is idempotent: entities use INSERT OR IGNORE and
the demo events are written once, together with a 'demo_seeded' flag, in a single
transaction - so repeated Streamlit reruns or restarts never duplicate records.
"""
from __future__ import annotations

import random
from datetime import date, datetime, timedelta

import config
from database.store import Database
from models.anomaly import AnomalyDetector
from models.pipeline import evaluate_access

SEED_FLAG = "demo_seeded"


def default_entities(today: date | None = None) -> dict:
    today = today or date.today()

    def ago(days: int) -> str:
        return (today - timedelta(days=days)).isoformat()

    users = [
        ("U-S01", "Aarav Mehta", "student", "verified", 1),
        ("U-S02", "Diya Rao", "student", "verified", 1),
        ("U-S03", "Kabir Nair", "student", "verified", 1),
        ("U-S04", "Meera Iyer", "student", "failed", 1),
        ("U-S05", "Rohan Das", "student", "verified", 0),
        ("U-S06", "Tara Joshi", "student", "verified", 1),
        ("U-F01", "Dr. Anita Sharma", "faculty", "verified", 1),
        ("U-F02", "Prof. Vikram Rao", "faculty", "verified", 1),
        ("U-F03", "Dr. Sunita Pillai", "faculty", "verified", 1),
        ("U-A01", "Rajesh Kumar", "admin", "verified", 1),
        ("U-A02", "Neha Kapoor", "admin", "verified", 1),
        ("U-A03", "Imran Sheikh", "admin", "verified", 1),
    ]
    devices = [
        ("D-S01L", "laptop", "U-S01", "compliant", ago(10)),
        ("D-S02L", "laptop", "U-S02", "compliant", ago(5)),
        ("D-S03P", "smartphone", "U-S03", "noncompliant", ago(40)),
        ("D-S04L", "laptop", "U-S04", "compliant", ago(8)),
        ("D-S05T", "tablet", "U-S05", "compliant", ago(20)),
        ("D-S06L", "laptop", "U-S06", "compliant", ago(3)),
        ("D-F01L", "laptop", "U-F01", "compliant", ago(7)),
        ("D-F02L", "laptop", "U-F02", "compliant", ago(15)),
        ("D-F03W", "workstation", "U-F03", "unknown", ago(60)),
        ("D-A01W", "workstation", "U-A01", "compliant", ago(2)),
        ("D-A02L", "laptop", "U-A02", "compliant", ago(12)),
        ("D-A03L", "laptop", "U-A03", "compliant", ago(100)),
    ]
    resources = [
        ("R-LMS", "Learning Management System", "Learning", 1, "student,faculty,admin"),
        ("R-LIB", "Digital Library Portal", "Library", 1, "student,faculty,admin"),
        ("R-LAB", "Computer Lab Cluster", "Laboratory", 2, "student,faculty,admin"),
        ("R-APP", "Internal Application Server", "Application", 2, "faculty,admin"),
        ("R-GRD", "Faculty Gradebook", "Application", 3, "faculty,admin"),
        ("R-ADM", "Administrative Records Server", "Administrative", 4, "admin"),
    ]
    # (id, name, role, category, max_sens, request_types, compliant, business_hours, description)
    policies = [
        ("P-01", "Student learning access", "student", "Learning", 2, "read,write", 1, 0,
         "Students may read and submit work on learning resources from a compliant device."),
        ("P-02", "Student library access", "student", "Library", 2, "read", 0, 0,
         "Library content is low risk, so a compliant device is not required."),
        ("P-03", "Student laboratory access", "student", "Laboratory", 2, "read,write", 1, 1,
         "Lab systems are available to students on compliant devices during business hours only."),
        ("P-04", "Faculty learning access", "faculty", "Learning", 3, "read,write,manage", 1, 0,
         "Faculty manage course content on the learning platform."),
        ("P-05", "Faculty library access", "faculty", "Library", 3, "read,write", 1, 0,
         "Faculty may read and contribute library material."),
        ("P-06", "Faculty laboratory access", "faculty", "Laboratory", 3, "read,write,manage", 1, 0,
         "Faculty may administer lab sessions."),
        ("P-07", "Faculty application access", "faculty", "Application", 3, "read,write", 1, 0,
         "Faculty use internal applications such as the gradebook (no manage rights)."),
        ("P-08", "Administrator general access", "admin", "*", 4, "read,write,manage", 1, 0,
         "Fallback policy: administrators on compliant devices, any category."),
        ("P-09", "Administrator sensitive records", "admin", "Administrative", 4, "read,write,manage", 1, 1,
         "Sensitive administrative resources only during business hours from a compliant device."),
    ]
    return {
        "users": [dict(zip(("user_id", "display_name", "role", "identity_status", "active"), u)) for u in users],
        "devices": [dict(zip(("device_id", "device_type", "owner_id", "compliance_status", "last_verified"), d),
                         active=1) for d in devices],
        "resources": [dict(zip(("resource_id", "name", "category", "sensitivity", "allowed_roles"), r), active=1)
                      for r in resources],
        "policies": [dict(zip(("policy_id", "name", "role", "resource_category", "max_sensitivity",
                               "request_types", "require_compliant_device", "business_hours_only",
                               "description"), p), enabled=1) for p in policies],
    }


# kind -> relative weight of that behaviour in the demo history
_KIND_WEIGHTS = {
    "normal": 60, "restricted": 8, "bad_identity": 5, "noncompliant": 5, "inactive": 3,
    "burst": 5, "brute_force": 4, "odd_hours": 5, "sweep": 5,
}


def _timestamp(rng: random.Random, now: datetime, hours=None) -> datetime:
    day = rng.randint(0, 6)
    hour = rng.choice(hours) if hours else min(23, max(0, int(rng.gauss(13, 3.5))))
    ts = (now - timedelta(days=day)).replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))
    return ts - timedelta(days=1) if ts > now else ts


def build_demo_events(db: Database, detector: AnomalyDetector, n: int = 130, seed: int = config.RANDOM_SEED,
                      now: datetime | None = None) -> list[dict]:
    """Run synthetic requests through the REAL pipeline (without persisting) and return the events."""
    now = (now or datetime.now()).replace(microsecond=0)
    rng = random.Random(seed)
    users = {u["user_id"]: u for u in db.list_entities("users")}
    devices = db.list_entities("devices")
    resources = db.list_entities("resources", active_only=True)
    good = [(users[d["owner_id"]], d) for d in devices
            if d["active"] and d["compliance_status"] == "compliant" and users[d["owner_id"]]["active"]
            and users[d["owner_id"]]["identity_status"] == "verified"]
    if not good or not resources:
        raise ValueError("Demo entities are missing; cannot build demo events.")

    def device_of(uid):
        return next(d for d in devices if d["owner_id"] == uid)

    kinds = rng.choices(list(_KIND_WEIGHTS), weights=list(_KIND_WEIGHTS.values()), k=n)
    events = []
    for kind in kinds:
        user, device = rng.choice(good)
        open_res = [r for r in resources if user["role"] in r["allowed_roles"].split(",")]
        res = rng.choice(open_res)
        rtype = rng.choice(["read", "read", "read", "write"])
        ctx: dict = {}
        ts = _timestamp(rng, now)
        if kind == "normal":
            ctx = {"requests_per_window": rng.randint(1, 6), "access_frequency": round(rng.uniform(10, 30), 1),
                   "distinct_resources": rng.randint(1, 3), "failed_request_ratio": round(rng.random() * 0.06, 3),
                   "failed_auth_count": rng.choice([0, 0, 0, 1])}
        elif kind == "restricted":
            target_id = rng.choice(["R-ADM", "R-ADM", "R-GRD", "R-APP"])
            res = next(r for r in resources if r["resource_id"] == target_id)
            if user["role"] == "admin":
                user, device = next((u, d) for u, d in good if u["role"] == "student")
            rtype = "manage"
        elif kind == "bad_identity":
            user, device = users["U-S04"], device_of("U-S04")
        elif kind == "noncompliant":
            user, device = users["U-S03"], device_of("U-S03")
        elif kind == "inactive":
            user, device = users["U-S05"], device_of("U-S05")
        elif kind == "burst":
            ctx = {"requests_per_window": rng.randint(25, 80), "failed_request_ratio": round(rng.random() * 0.2, 2)}
        elif kind == "brute_force":
            ctx = {"failed_auth_count": rng.randint(4, 10), "failed_request_ratio": round(rng.uniform(0.4, 0.9), 2),
                   "requests_per_window": rng.randint(5, 14)}
        elif kind == "odd_hours":
            ts = _timestamp(rng, now, hours=[0, 1, 2, 3, 4, 23])
            ctx = {"requests_per_window": rng.randint(9, 20), "distinct_resources": rng.randint(2, 5)}
        elif kind == "sweep":
            ctx = {"distinct_resources": rng.randint(6, 12), "requests_per_window": rng.randint(8, 20)}
        # restricted / bad_identity / noncompliant / inactive keep the default behavioural context
        request = {"user_id": user["user_id"], "device_id": device["device_id"],
                   "resource_id": res["resource_id"], "request_type": rtype}
        result = evaluate_access(db, detector, request, ctx, now=ts, event_type="seed_simulated", persist=False)
        events.append(result["event"])
    events.sort(key=lambda e: e["timestamp"])
    return events


def ensure_seeded(db: Database, detector: AnomalyDetector, force_events: bool = False,
                  now: datetime | None = None) -> bool:
    """Create demo entities and demo events if they are not there yet. Returns True if events were added."""
    entities = default_entities()
    db.seed_entities(entities["users"], entities["devices"], entities["resources"], entities["policies"])
    if db.get_setting(SEED_FLAG) == "1" and not force_events:
        return False
    events = build_demo_events(db, detector, now=now)
    db.add_events(events, extra_settings={SEED_FLAG: "1"})
    return True


def bootstrap(db_path=config.DB_PATH) -> tuple[Database, AnomalyDetector]:
    """Open the database, train the detector (never raises) and seed demo data once."""
    db = Database(db_path)
    detector = AnomalyDetector().fit()
    ensure_seeded(db, detector)
    return db, detector
