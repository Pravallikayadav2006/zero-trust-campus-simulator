"""Page 3 - Zero Trust Policy Engine: view, edit and add policies; configure risk handling."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

import config  # noqa: E402
from data.scenarios import get_scenario  # noqa: E402
from database.store import DuplicateIdError  # noqa: E402
from models.pipeline import evaluate_access  # noqa: E402
from models.policy_engine import build_policy_matrix  # noqa: E402
from utils import ui  # noqa: E402
from utils.validation import split_csv, validate_policy  # noqa: E402

db, detector = ui.get_runtime()
CATEGORIES = list(config.RESOURCE_CATEGORIES) + ["*"]
SENS = list(config.SENSITIVITY_LEVELS)

st.title("Zero Trust Policy Engine")
st.caption("Mandatory checks decide access. Risk and anomaly signals can only add scrutiny - they can never "
           "override a failed mandatory check. Edits below apply to the very next request.")

policies = db.list_entities("policies")
resources = db.list_entities("resources")
tab_table, tab_edit, tab_risk, tab_rules = st.tabs(["Policy table", "Edit policies", "Risk handling", "Decision rules"])

# ---------------------------------------------------------------------------- table
with tab_table:
    st.markdown("**Role x resource matrix** - what each role could do on each resource when identity, device and "
                "time conditions are all satisfied.")
    matrix = pd.DataFrame(build_policy_matrix(resources, policies))
    role_filter = st.multiselect("Filter by role", list(config.ROLES), default=list(config.ROLES))
    ui.show_df(matrix[matrix["Role"].isin(role_filter)] if role_filter else matrix)
    st.markdown("**Configured policies**")
    raw = pd.DataFrame(policies)
    if not raw.empty:
        raw["require_compliant_device"] = raw["require_compliant_device"].map({1: "yes", 0: "no"})
        raw["business_hours_only"] = raw["business_hours_only"].map({1: "yes", 0: "no"})
        raw["enabled"] = raw["enabled"].map({1: "enabled", 0: "disabled"})
        ui.show_df(raw.rename(columns={
            "policy_id": "ID", "name": "Name", "role": "Role", "resource_category": "Category",
            "max_sensitivity": "Max sensitivity", "request_types": "Request types",
            "require_compliant_device": "Compliant device", "business_hours_only": "Business hours only",
            "enabled": "Status", "description": "Description"}))
    st.caption("Default deny: if no enabled policy grants a role access to a resource category, the request is denied.")

# ---------------------------------------------------------------------------- edit
with tab_edit:
    ids = [p["policy_id"] for p in policies]
    by_id = {p["policy_id"]: p for p in policies}
    pid = st.selectbox("Policy to edit", ids, format_func=lambda i: f"{i} - {by_id[i]['name']}")
    p = by_id[pid]
    with st.form(f"edit_policy_{pid}"):
        name = st.text_input("Name", p["name"])
        c1, c2, c3 = st.columns(3)
        role = c1.selectbox("Role", config.ROLES, index=config.ROLES.index(p["role"]))
        category = c2.selectbox("Resource category", CATEGORIES, index=CATEGORIES.index(p["resource_category"]),
                                help="'*' applies to every category unless a specific policy exists.")
        max_sens = c3.selectbox("Maximum sensitivity", SENS, index=SENS.index(p["max_sensitivity"]),
                                format_func=lambda s: f"{s} - {config.SENSITIVITY_LEVELS[s]}")
        types = st.multiselect("Allowed request types", config.REQUEST_TYPES, default=split_csv(p["request_types"]))
        k1, k2, k3 = st.columns(3)
        compliant = k1.checkbox("Require compliant device", bool(p["require_compliant_device"]))
        hours = k2.checkbox("Business hours only", bool(p["business_hours_only"]),
                            help=f"Allowed between {config.BUSINESS_HOURS[0]:02d}:00 and {config.BUSINESS_HOURS[1]:02d}:00.")
        enabled = k3.checkbox("Enabled", bool(p["enabled"]))
        description = st.text_area("Description", p["description"])
        saved = st.form_submit_button("Save policy", type="primary")
    if saved:
        data = {"policy_id": pid, "name": name, "role": role, "resource_category": category,
                "max_sensitivity": max_sens, "request_types": ",".join(types)}
        errors = validate_policy(data, ids, is_new=False)
        if errors:
            for e in errors:
                st.error(e)
        else:
            db.update_entity("policies", pid, {
                "name": name.strip(), "role": role, "resource_category": category, "max_sensitivity": max_sens,
                "request_types": ",".join(types), "require_compliant_device": int(compliant),
                "business_hours_only": int(hours), "enabled": int(enabled), "description": description.strip()})
            st.success(f"Policy {pid} saved. It applies to all future requests.")
            st.rerun()

    with st.expander("Add a new policy"):
        with st.form("add_policy", clear_on_submit=True):
            n_id = st.text_input("Policy ID", placeholder="P-10")
            n_name = st.text_input("Name")
            a1, a2, a3 = st.columns(3)
            n_role = a1.selectbox("Role", config.ROLES, key="np_role")
            n_cat = a2.selectbox("Resource category", CATEGORIES, key="np_cat")
            n_sens = a3.selectbox("Maximum sensitivity", SENS, key="np_sens",
                                  format_func=lambda s: f"{s} - {config.SENSITIVITY_LEVELS[s]}")
            n_types = st.multiselect("Allowed request types", config.REQUEST_TYPES, default=["read"], key="np_types")
            n_comp = st.checkbox("Require compliant device", True, key="np_comp")
            n_hours = st.checkbox("Business hours only", False, key="np_hours")
            n_desc = st.text_area("Description", key="np_desc")
            added = st.form_submit_button("Add policy")
        if added:
            data = {"policy_id": n_id.strip(), "name": n_name, "role": n_role, "resource_category": n_cat,
                    "max_sensitivity": n_sens, "request_types": ",".join(n_types)}
            errors = validate_policy(data, ids, is_new=True)
            if errors:
                for e in errors:
                    st.error(e)
            else:
                try:
                    db.insert_entity("policies", {**data, "name": n_name.strip(), "require_compliant_device": int(n_comp),
                                                  "business_hours_only": int(n_hours), "enabled": 1,
                                                  "description": n_desc.strip()})
                    st.success(f"Policy {data['policy_id']} added.")
                    st.rerun()
                except (DuplicateIdError, sqlite3.IntegrityError) as exc:
                    st.error(str(exc))

# ---------------------------------------------------------------------------- risk handling
with tab_risk:
    th = db.get_thresholds()
    st.markdown("These thresholds are applied **only after every mandatory check has passed**.")
    flag_t = st.slider("Flag when risk score is at least", 0, 100, int(th["risk_flag_threshold"]))
    deny_t = st.slider("Deny when risk score is at least", 0, 100, int(th["risk_deny_threshold"]))
    if st.button("Save thresholds", type="primary"):
        if flag_t >= deny_t:
            st.error("The flag threshold must be lower than the deny threshold.")
        else:
            db.set_setting("risk_flag_threshold", flag_t)
            db.set_setting("risk_deny_threshold", deny_t)
            st.success("Thresholds saved. They apply to all future requests.")
    st.caption(f"Defaults: flag at {config.DEFAULT_SETTINGS['risk_flag_threshold']:g}, "
               f"deny at {config.DEFAULT_SETTINGS['risk_deny_threshold']:g}.")

# ---------------------------------------------------------------------------- rules
with tab_rules:
    st.markdown("""
**Zero Trust principles implemented**
- Never trust by location: network position is not an input to any check.
- Verify identity first: account must be active and identity verified.
- Least privilege: a role needs an explicit enabled policy for the category, sensitivity and request type.
- Device compliance and device-to-user binding are verified per policy.
- Every decision (including denials and malformed requests) is written to the audit log.

**Precedence (highest first)**
1. **R1** Any mandatory check fails -> **DENY**. Risk and anomaly results are shown but ignored.
2. **R2** Risk score >= deny threshold -> **DENY**.
3. **R3** Risk score >= flag threshold, or an anomaly is detected -> **FLAG** (permitted but flagged for review).
4. **R4** Otherwise -> **ALLOW**.

A "normal" anomaly result or a low risk score can never create access, because ALLOW is only reachable after R1 passes.
""")
    st.markdown("**Example scenarios, evaluated live with the current policies (not saved to the log)**")
    labels = {1: "A. Verified student, compliant device, learning resource", 2: "B. Student requests admin-only resource",
              3: "C. Invalid identity verification", 4: "D. Noncompliant device, protected resource",
              5: "E. Unusual behaviour (repeated failed sign-ins)"}
    rows = []
    for sid, label in labels.items():
        s = get_scenario(sid)
        r = evaluate_access(db, detector, s["request"], s["context"], persist=False)
        rows.append({"Example": label, "Mandatory checks": r["policy_verdict"], "Anomaly": r["anomaly_verdict"],
                     "Decision": r["decision"], "Why": r["reason"]})
    ui.show_df(pd.DataFrame(rows))
