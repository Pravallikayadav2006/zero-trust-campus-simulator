"""Page 7 - Users, Devices and Resources: validated add / edit / (de)activate forms."""
import sqlite3
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

import config  # noqa: E402
from database.store import DuplicateIdError  # noqa: E402
from utils import ui  # noqa: E402
from utils.validation import split_csv, validate_device, validate_resource, validate_user  # noqa: E402

db, detector = ui.get_runtime()
SENS = list(config.SENSITIVITY_LEVELS)


def sens_label(s: int) -> str:
    return f"{s} - {config.SENSITIVITY_LEVELS[s]}"


def insert(table: str, data: dict, label: str) -> None:
    try:
        db.insert_entity(table, data)
    except (DuplicateIdError, sqlite3.IntegrityError) as exc:
        st.error(str(exc))
    else:
        st.success(f"{label} added. It is used by all future requests.")
        st.rerun()


def show_errors(errors: list[str]) -> None:
    for e in errors:
        st.error(e)


st.title("Users, Devices and Resources")
st.caption("Fictional entities only. Changes here take effect on the next simulated request. "
           "Entities are deactivated rather than deleted, so audit history keeps its references.")

users = db.list_entities("users")
devices = db.list_entities("devices")
resources = db.list_entities("resources")
user_ids = [u["user_id"] for u in users]
tab_u, tab_d, tab_r = st.tabs([f"Users ({len(users)})", f"Devices ({len(devices)})", f"Resources ({len(resources)})"])

# ----------------------------------------------------------------------------- users
with tab_u:
    frame = pd.DataFrame(users)
    frame["active"] = frame["active"].map({1: "active", 0: "inactive"})
    ui.show_df(frame.rename(columns={"user_id": "User ID", "display_name": "Name", "role": "Role",
                                     "identity_status": "Identity", "active": "Status"}))
    left, right = st.columns(2)
    with left.container(border=True):
        st.markdown("**Add user**")
        with st.form("add_user", clear_on_submit=True):
            uid = st.text_input("User ID", placeholder="U-S07")
            name = st.text_input("Display name (fictional)")
            role = st.selectbox("Role", config.ROLES)
            ident = st.selectbox("Identity verification", config.IDENTITY_STATUSES)
            ok = st.form_submit_button("Add user")
        if ok:
            data = {"user_id": uid.strip(), "display_name": name.strip(), "role": role, "identity_status": ident}
            errors = validate_user(data, user_ids)
            show_errors(errors) if errors else insert("users", {**data, "active": 1}, f"User {data['user_id']}")
    with right.container(border=True):
        st.markdown("**Edit or deactivate user**")
        by_id = {u["user_id"]: u for u in users}
        sel = st.selectbox("User", user_ids, format_func=lambda i: ui.user_label(by_id[i]), key="eu_sel")
        u = by_id[sel]
        with st.form(f"edit_user_{sel}"):
            e_name = st.text_input("Display name", u["display_name"])
            e_role = st.selectbox("Role", config.ROLES, index=config.ROLES.index(u["role"]))
            e_ident = st.selectbox("Identity verification", config.IDENTITY_STATUSES,
                                   index=config.IDENTITY_STATUSES.index(u["identity_status"]))
            e_active = st.checkbox("Account active", bool(u["active"]))
            saved = st.form_submit_button("Save changes", type="primary")
        if saved:
            data = {"user_id": sel, "display_name": e_name.strip(), "role": e_role, "identity_status": e_ident}
            errors = validate_user(data, user_ids, is_new=False)
            if errors:
                show_errors(errors)
            else:
                db.update_entity("users", sel, {"display_name": data["display_name"], "role": e_role,
                                                "identity_status": e_ident, "active": int(e_active)})
                st.success(f"User {sel} updated.")
                st.rerun()

# ----------------------------------------------------------------------------- devices
with tab_d:
    frame = pd.DataFrame(devices)
    frame["active"] = frame["active"].map({1: "active", 0: "inactive"})
    ui.show_df(frame.rename(columns={"device_id": "Device ID", "device_type": "Type", "owner_id": "Owner",
                                     "compliance_status": "Compliance", "last_verified": "Last verified",
                                     "active": "Status"}))
    left, right = st.columns(2)
    with left.container(border=True):
        st.markdown("**Add device**")
        with st.form("add_device", clear_on_submit=True):
            did = st.text_input("Device ID", placeholder="D-S07L")
            dtype = st.selectbox("Device type", config.DEVICE_TYPES)
            owner = st.selectbox("Owner", user_ids, format_func=lambda i: ui.user_label(by_id[i]))
            comp = st.selectbox("Compliance status", config.COMPLIANCE_STATUSES)
            verified = st.date_input("Last simulated verification", date.today(), max_value=date.today())
            ok = st.form_submit_button("Add device")
        if ok:
            data = {"device_id": did.strip(), "device_type": dtype, "owner_id": owner, "compliance_status": comp,
                    "last_verified": verified.isoformat()}
            errors = validate_device(data, [d["device_id"] for d in devices], user_ids)
            show_errors(errors) if errors else insert("devices", {**data, "active": 1}, f"Device {data['device_id']}")
    with right.container(border=True):
        st.markdown("**Edit or deactivate device**")
        dby = {d["device_id"]: d for d in devices}
        dsel = st.selectbox("Device", list(dby), format_func=lambda i: ui.device_label(dby[i]), key="ed_sel")
        d = dby[dsel]
        with st.form(f"edit_device_{dsel}"):
            e_type = st.selectbox("Device type", config.DEVICE_TYPES, index=config.DEVICE_TYPES.index(d["device_type"]))
            e_owner = st.selectbox("Owner", user_ids, index=user_ids.index(d["owner_id"]) if d["owner_id"] in user_ids else 0,
                                   format_func=lambda i: ui.user_label(by_id[i]))
            e_comp = st.selectbox("Compliance status", config.COMPLIANCE_STATUSES,
                                  index=config.COMPLIANCE_STATUSES.index(d["compliance_status"]))
            try:
                current = date.fromisoformat(d["last_verified"])
            except (TypeError, ValueError):
                current = date.today()
            e_ver = st.date_input("Last simulated verification", min(current, date.today()), max_value=date.today())
            e_active = st.checkbox("Device active", bool(d["active"]))
            saved = st.form_submit_button("Save changes", type="primary")
        if saved:
            data = {"device_id": dsel, "device_type": e_type, "owner_id": e_owner, "compliance_status": e_comp,
                    "last_verified": e_ver.isoformat()}
            errors = validate_device(data, [], user_ids, is_new=False)
            if errors:
                show_errors(errors)
            else:
                db.update_entity("devices", dsel, {"device_type": e_type, "owner_id": e_owner,
                                                   "compliance_status": e_comp, "last_verified": data["last_verified"],
                                                   "active": int(e_active)})
                st.success(f"Device {dsel} updated.")
                st.rerun()

# ----------------------------------------------------------------------------- resources
with tab_r:
    frame = pd.DataFrame(resources)
    frame["sensitivity"] = frame["sensitivity"].map(sens_label)
    frame["active"] = frame["active"].map({1: "active", 0: "inactive"})
    ui.show_df(frame.rename(columns={"resource_id": "Resource ID", "name": "Name", "category": "Category",
                                     "sensitivity": "Sensitivity", "allowed_roles": "Allowed roles",
                                     "active": "Status"}))
    st.caption("Allowed roles act together with the access policies on the Policy Engine page: both must permit "
               "the request (least privilege).")
    left, right = st.columns(2)
    with left.container(border=True):
        st.markdown("**Add resource**")
        with st.form("add_resource", clear_on_submit=True):
            rid = st.text_input("Resource ID", placeholder="R-NEW")
            rname = st.text_input("Resource name")
            rcat = st.selectbox("Category", config.RESOURCE_CATEGORIES)
            rsens = st.selectbox("Sensitivity level", SENS, format_func=sens_label)
            rroles = st.multiselect("Allowed roles", config.ROLES, default=["admin"])
            ok = st.form_submit_button("Add resource")
        if ok:
            data = {"resource_id": rid.strip(), "name": rname.strip(), "category": rcat, "sensitivity": rsens,
                    "allowed_roles": ",".join(rroles)}
            errors = validate_resource(data, [r["resource_id"] for r in resources])
            show_errors(errors) if errors else insert("resources", {**data, "active": 1}, f"Resource {data['resource_id']}")
    with right.container(border=True):
        st.markdown("**Edit or deactivate resource**")
        rby = {r["resource_id"]: r for r in resources}
        rsel = st.selectbox("Resource", list(rby), format_func=lambda i: ui.resource_label(rby[i]), key="er_sel")
        r = rby[rsel]
        with st.form(f"edit_resource_{rsel}"):
            e_name = st.text_input("Resource name", r["name"])
            e_cat = st.selectbox("Category", config.RESOURCE_CATEGORIES,
                                 index=config.RESOURCE_CATEGORIES.index(r["category"]))
            e_sens = st.selectbox("Sensitivity level", SENS, index=SENS.index(r["sensitivity"]), format_func=sens_label)
            e_roles = st.multiselect("Allowed roles", config.ROLES, default=split_csv(r["allowed_roles"]))
            e_active = st.checkbox("Resource active", bool(r["active"]))
            saved = st.form_submit_button("Save changes", type="primary")
        if saved:
            data = {"resource_id": rsel, "name": e_name.strip(), "category": e_cat, "sensitivity": e_sens,
                    "allowed_roles": ",".join(e_roles)}
            errors = validate_resource(data, [], is_new=False)
            if errors:
                show_errors(errors)
            else:
                db.update_entity("resources", rsel, {"name": data["name"], "category": e_cat, "sensitivity": e_sens,
                                                     "allowed_roles": data["allowed_roles"], "active": int(e_active)})
                st.success(f"Resource {rsel} updated.")
                st.rerun()
