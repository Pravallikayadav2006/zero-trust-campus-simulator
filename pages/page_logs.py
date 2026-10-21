"""Page 6 - Security Event Logs: search, filter, sort, inspect, export, and (guarded) clear."""
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

import config  # noqa: E402
from data.seed import ensure_seeded  # noqa: E402
from database.store import EVENT_COLUMNS  # noqa: E402
from utils import ui  # noqa: E402
from utils.export import events_to_csv, validate_csv  # noqa: E402

db, detector = ui.get_runtime()

st.title("Security Event Logs")
st.caption("Persistent audit trail stored in SQLite. Every decision is recorded and survives restarts. "
           "All records are simulated and fictional.")

all_events = db.query_events()
if all_events.empty:
    st.info("The audit log is empty. Submit a request in the Campus Network Simulator, run a scenario, "
            "or add demo events below.")
else:
    dates = pd.to_datetime(all_events["timestamp"])
    first_day, last_day = dates.min().date(), max(dates.max().date(), date.today())
    with st.container(border=True):
        f1, f2, f3 = st.columns([2, 2, 3])
        span = f1.date_input("Date range", (first_day, last_day), min_value=first_day, max_value=last_day)
        decisions = f2.multiselect("Decision", list(config.DECISIONS))
        search = f3.text_input("Search", placeholder="user, device, resource or words in the reason")
        g1, g2, g3, g4 = st.columns(4)
        roles = g1.multiselect("Role", list(config.ROLES))
        res_ids = g2.multiselect("Resource", sorted(all_events["resource_id"].dropna().unique()))
        etypes = g3.multiselect("Event type", list(config.EVENT_TYPES))
        sort_by = g4.selectbox("Sort by", ["timestamp", "event_id", "risk_score", "anomaly_score", "decision",
                                           "user_id", "resource_id"])
        ascending = st.radio("Order", ["Newest / highest first", "Oldest / lowest first"], horizontal=True) \
            == "Oldest / lowest first"

    start = end = None
    if isinstance(span, (tuple, list)) and len(span) == 2:
        start, end = f"{span[0]} 00:00:00", f"{span[1]} 23:59:59"
    elif isinstance(span, (tuple, list)) and len(span) == 1:
        start, end = f"{span[0]} 00:00:00", f"{span[0]} 23:59:59"

    events = db.query_events(start=start, end=end, roles=roles, resources=res_ids, event_types=etypes,
                             decisions=decisions, search=search.strip() or None, sort_by=sort_by, ascending=ascending)
    st.markdown(f"**{len(events)}** of {len(all_events)} events match the filters.")

    if events.empty:
        st.warning("No events match these filters. Widen the date range or clear a filter.")
    else:
        view = events[["event_id", "timestamp", "user_id", "user_role", "device_id", "resource_id", "request_type",
                       "event_type", "risk_score", "anomaly_flag", "decision", "reason"]].copy()
        view["anomaly_flag"] = view["anomaly_flag"].map({1: "anomaly", 0: "normal"})
        ui.show_df(view.rename(columns={"event_id": "Event", "timestamp": "Time", "user_id": "User",
                                        "user_role": "Role", "device_id": "Device", "resource_id": "Resource",
                                        "request_type": "Type", "event_type": "Source", "risk_score": "Risk",
                                        "anomaly_flag": "Anomaly", "decision": "Decision", "reason": "Reason"}))

        try:
            csv_text = events_to_csv(events)
            problems = validate_csv(csv_text, len(events))
        except ValueError as exc:
            csv_text, problems = "", [str(exc)]
        if problems:
            st.error("The CSV export failed validation: " + " ".join(problems))
        else:
            st.download_button(f"Export {len(events)} filtered event(s) to CSV", csv_text,
                               file_name="audit_log_export.csv", mime="text/csv", type="primary")
            st.caption("The export contains only fictional demo identities. Cells that could be read as spreadsheet "
                       "formulas are neutralised.")

        st.subheader("Event details")
        shown_ids = events["event_id"].head(500).tolist()
        chosen = st.selectbox("Select an event", shown_ids, format_func=lambda i: f"Event #{i}")
        ev = db.get_event(chosen)
        if ev:
            st.markdown(f"{ui.pill(ev['decision'])} &nbsp; {ev['timestamp']} &nbsp; ({ev['event_type']}, "
                        f"{'simulated' if ev['is_simulated'] else 'real'})", unsafe_allow_html=True)
            st.write(ev["reason"])
            d1, d2, d3 = st.columns(3)
            d1.write(f"**User:** {ev['user_id']} ({ev['user_role'] or 'unknown role'})  \n**Device:** {ev['device_id']}")
            d2.write(f"**Resource:** {ev['resource_id']}  \n**Request type:** {ev['request_type']}  \n"
                     f"**Policy:** {ev['policy_id'] or 'none'}")
            d3.write(f"**Risk:** {ev['risk_score']} ({ev['risk_level']})  \n**Anomaly indicator:** {ev['anomaly_score']} "
                     f"({ev['anomaly_method']})")
            checks = json.loads(ev["policy_checks"] or "[]")
            if checks:
                ui.show_df(ui.checks_frame(checks))
            factors = json.loads(ev["risk_factors"] or "[]")
            if factors:
                ui.show_df(pd.DataFrame(factors))
            with st.expander("Behavioural context (raw)"):
                st.json(json.loads(ev["context"]) if ev["context"] else {})

st.divider()
with st.expander("Manage audit data"):
    if st.button("Add another batch of demo events"):
        ensure_seeded(db, detector, force_events=True)
        st.success("Added a batch of synthetic demo events.")
        st.rerun()
    st.warning("**Danger zone.** Clearing deletes every audit event permanently. Users, devices, resources and "
               "policies are kept. This cannot be undone.")
    confirm = st.checkbox("I understand that all audit events will be deleted")
    typed = st.text_input("Type DELETE to confirm")
    if st.button("Clear all audit events", disabled=not (confirm and typed == "DELETE")):
        removed = db.clear_events()
        st.success(f"Deleted {removed} event(s).")
        st.rerun()
