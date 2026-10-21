"""Contextual risk scoring (deterministic, rule based).

The score only matters AFTER every mandatory policy check has passed. A low
score can never turn a denial into an allow.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime

import config


@dataclass
class RiskResult:
    score: float
    level: str
    factors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def risk_level(score: float, flag_threshold: float, deny_threshold: float) -> str:
    if score >= deny_threshold:
        return "High"
    if score >= flag_threshold:
        return "Medium"
    return "Low"


def _days_since(value, now: datetime):
    try:
        return (now.date() - date.fromisoformat(str(value))).days
    except (TypeError, ValueError):
        return None


def score_risk(
    context: dict,
    device: dict | None,
    resource: dict | None,
    now: datetime,
    flag_threshold: float = config.DEFAULT_SETTINGS["risk_flag_threshold"],
    deny_threshold: float = config.DEFAULT_SETTINGS["risk_deny_threshold"],
) -> RiskResult:
    """Add up transparent risk factors (max 100)."""
    factors: list[dict] = []

    def add(name, points, detail):
        if points > 0:
            factors.append({"factor": name, "points": round(float(points), 1), "detail": detail})

    failed = context["failed_auth_count"]
    add("Failed authentication", min(failed, 5) * 6, f"{failed} failed attempt(s), 6 points each (max 30)")

    lo, hi = config.UNUSUAL_HOURS
    hour = context["hour"]
    if hour < lo or hour >= hi:
        add("Unusual access time", 15, f"request at {hour:02d}:00 is outside {lo:02d}:00-{hi:02d}:00")

    expected = context["access_frequency"] / config.WINDOWS_PER_HOUR
    deviation = (context["requests_per_window"] - expected) / max(expected, 1.0)
    if deviation > 1:
        add("Request-rate deviation", min(deviation * 5, 20),
            f"{context['requests_per_window']} requests vs about {expected:.1f} expected")

    distinct = context["distinct_resources"]
    if distinct > 3:
        add("Wide resource spread", min((distinct - 3) * 5, 15), f"{distinct} distinct resources in one window")

    ratio = context["failed_request_ratio"]
    add("Failed-request ratio", ratio * 15, f"{ratio:.0%} of requests failed")

    if resource is not None:
        sens = int(resource.get("sensitivity", 1))
        add("Resource sensitivity", (sens - 1) * 3,
            f"{config.SENSITIVITY_LEVELS.get(sens, sens)} sensitivity resource")

    if device is not None:
        age = _days_since(device.get("last_verified"), now)
        if age is None:
            add("Stale device verification", 10, "device has no valid verification date")
        elif age > 90:
            add("Stale device verification", 10, f"last verified {age} days ago (over 90)")
        elif age > 30:
            add("Stale device verification", 5, f"last verified {age} days ago (over 30)")

    score = round(min(100.0, sum(f["points"] for f in factors)), 1)
    return RiskResult(score=score, level=risk_level(score, flag_threshold, deny_threshold), factors=factors)
