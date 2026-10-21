"""Input validation helpers. Every form and request is validated here."""
from __future__ import annotations

import math
import re
from datetime import date

import config

ID_PATTERN = re.compile(r"^[A-Z]{1,3}-[A-Za-z0-9]{1,10}$")
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,'&()/\-]{0,79}$")


def split_csv(value) -> list[str]:
    """Turn 'a,b' or ['a', 'b'] into a clean list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split(",")
    else:
        items = list(value)
    return [str(i).strip() for i in items if str(i).strip()]


def validate_id(value, label: str = "ID") -> list[str]:
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        return [f"{label} must look like 'U-S01': 1-3 capital letters, a dash, then 1-10 letters or digits."]
    return []


def validate_name(value, label: str = "Name") -> list[str]:
    if not isinstance(value, str) or not NAME_PATTERN.match(value.strip()):
        return [f"{label} must be 1-80 characters using letters, digits and basic punctuation only."]
    return []


def _in(value, allowed, label) -> list[str]:
    if value not in allowed:
        return [f"{label} must be one of: {', '.join(str(a) for a in allowed)}."]
    return []


def validate_user(data: dict, existing_ids=(), is_new: bool = True) -> list[str]:
    errors: list[str] = []
    uid = str(data.get("user_id", "")).strip()
    errors += validate_id(uid, "User ID")
    if is_new and uid in set(existing_ids):
        errors.append(f"User ID '{uid}' already exists.")
    errors += validate_name(data.get("display_name", ""), "Display name")
    errors += _in(data.get("role"), config.ROLES, "Role")
    errors += _in(data.get("identity_status"), config.IDENTITY_STATUSES, "Identity status")
    return errors


def validate_device(data: dict, existing_ids=(), user_ids=(), is_new: bool = True) -> list[str]:
    errors: list[str] = []
    did = str(data.get("device_id", "")).strip()
    errors += validate_id(did, "Device ID")
    if is_new and did in set(existing_ids):
        errors.append(f"Device ID '{did}' already exists.")
    errors += _in(data.get("device_type"), config.DEVICE_TYPES, "Device type")
    if data.get("owner_id") not in set(user_ids):
        errors.append("Owner must be an existing registered user.")
    errors += _in(data.get("compliance_status"), config.COMPLIANCE_STATUSES, "Compliance status")
    lv = data.get("last_verified")
    try:
        parsed = date.fromisoformat(str(lv))
        if parsed > date.today():
            errors.append("Last verification date cannot be in the future.")
    except ValueError:
        errors.append("Last verification must be a valid date (YYYY-MM-DD).")
    return errors


def validate_resource(data: dict, existing_ids=(), is_new: bool = True) -> list[str]:
    errors: list[str] = []
    rid = str(data.get("resource_id", "")).strip()
    errors += validate_id(rid, "Resource ID")
    if is_new and rid in set(existing_ids):
        errors.append(f"Resource ID '{rid}' already exists.")
    errors += validate_name(data.get("name", ""), "Resource name")
    errors += _in(data.get("category"), config.RESOURCE_CATEGORIES, "Category")
    errors += _in(data.get("sensitivity"), tuple(config.SENSITIVITY_LEVELS), "Sensitivity level")
    roles = split_csv(data.get("allowed_roles"))
    if not roles:
        errors.append("Select at least one allowed role.")
    elif not set(roles) <= set(config.ROLES):
        errors.append("Allowed roles contain an unknown role.")
    return errors


def validate_policy(data: dict, existing_ids=(), is_new: bool = True) -> list[str]:
    errors: list[str] = []
    pid = str(data.get("policy_id", "")).strip()
    errors += validate_id(pid, "Policy ID")
    if is_new and pid in set(existing_ids):
        errors.append(f"Policy ID '{pid}' already exists.")
    errors += validate_name(data.get("name", ""), "Policy name")
    errors += _in(data.get("role"), config.ROLES, "Role")
    errors += _in(data.get("resource_category"), config.RESOURCE_CATEGORIES + ("*",), "Resource category")
    errors += _in(data.get("max_sensitivity"), tuple(config.SENSITIVITY_LEVELS), "Maximum sensitivity")
    types = split_csv(data.get("request_types"))
    if not types:
        errors.append("Select at least one request type.")
    elif not set(types) <= set(config.REQUEST_TYPES):
        errors.append("Request types contain an unknown value.")
    return errors


def validate_request(request) -> list[str]:
    """Check the shape of an access request before any lookup happens."""
    if not isinstance(request, dict):
        return ["Request must be a dictionary of fields."]
    errors: list[str] = []
    for key, label in (("user_id", "User ID"), ("device_id", "Device ID"), ("resource_id", "Resource ID")):
        errors += validate_id(request.get(key), label)
    errors += _in(request.get("request_type"), config.REQUEST_TYPES, "Request type")
    return errors


# (field, kind, minimum, maximum)
_CONTEXT_FIELDS = (
    ("hour", "int", 0, 23),
    ("failed_auth_count", "int", 0, 50),
    ("requests_per_window", "int", 0, 500),
    ("access_frequency", "float", 0.0, 1000.0),
    ("distinct_resources", "int", 0, 50),
    ("failed_request_ratio", "float", 0.0, 1.0),
)


def normalize_context(context: dict | None, default_hour: int) -> dict:
    """Fill defaults and validate behavioural context. Raises ValueError on bad input."""
    merged = dict(config.DEFAULT_CONTEXT)
    merged.update({k: v for k, v in (context or {}).items() if v is not None})
    if merged.get("hour") is None:
        merged["hour"] = default_hour
    unknown = set(merged) - {f[0] for f in _CONTEXT_FIELDS}
    if unknown:
        raise ValueError(f"Unknown context field(s): {', '.join(sorted(unknown))}.")
    clean: dict = {}
    for name, kind, lo, hi in _CONTEXT_FIELDS:
        raw = merged[name]
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"Context field '{name}' must be a number.")
        if isinstance(raw, float) and math.isnan(raw):
            raise ValueError(f"Context field '{name}' must not be NaN.")
        if not lo <= raw <= hi:
            raise ValueError(f"Context field '{name}' must be between {lo} and {hi}.")
        clean[name] = int(raw) if kind == "int" else float(raw)
    return clean
