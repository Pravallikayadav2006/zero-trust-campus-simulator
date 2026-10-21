"""Page 1 - Executive Overview. Every number is computed from stored audit events and entities."""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from data.scenarios import random_request  # noqa: E402
from models.pipeline import evaluate_access  # noqa: E402
from utils import ui, visualization as viz  # noqa: E402

db, detector = ui.get_runtime()


def run_quick_action(kind: str) -> None:
    """Button callback: generate one simulated request, run it through the real pipeline, save it."""
    database, det = ui.get_runtime()
    try:
        request, context, label = random_request(database, kind)
        result = evaluate_access(database, det, request, context, event_type="quick_action")
        st.session_state["quick_result"] = (label, result)
        st.session_state.pop("quick_error", None)
    except ValueError as exc:
        st.session_state["quick_error"] = str(exc)


st.title("Executive Overview")
st.caption("Live view of the simulated campus. All figures come from the audit log and the registered entities.")

events = db.query_events()
users, devices = db.list_entities("users"), db.list_entities("devices")

# ------------------------------------------------------------------ request metrics
total = len(events)
allowed = int((events["decision"] == "ALLOW").sum())
denied = int((events["decision"] == "DENY").sum())
flagged = int((events["decision"] == "FLAG").sum())
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total simulated requests", f"{total:,}", help="Every access request ever recorded in the audit log.")
m2.metric("Allowed", f"{allowed:,}", help="All mandatory checks passed and risk was low.")
m3.metric("Denied", f"{denied:,}", help="A mandatory check failed or the risk score reached the deny threshold.")
m4.metric("Suspicious flagged", f"{flagged:,}",
          help="Permitted by policy but flagged: risk above the flag threshold or an anomaly was detected.")

e1, e2, e3, e4 = st.columns(4)
e1.metric("Registered users", f"{sum(1 for u in users if u['active'])} active / {len(users)}")
e2.metric("Registered devices", f"{sum(1 for d in devices if d['active'])} active / {len(devices)}")
e3.metric("Unique users in log", int(events["user_id"].nunique()))
e4.metric("Unique devices in log", int(events["device_id"].nunique()))
st.caption("Requests count every access attempt; users and devices count distinct identities, so many "
           "requests can come from few users.")

# ------------------------------------------------------------------ quick actions
with st.container(border=True):
    st.markdown("**Quick actions** - generate one simulated request and add it to the audit log")
    b1, b2, _ = st.columns([1, 1, 2])
    b1.button("Generate normal activity", on_click=run_quick_action, args=("normal",), type="primary")
    b2.button("Generate suspicious activity", on_click=run_quick_action, args=("suspicious",))
    if st.session_state.get("quick_error"):
        st.error(st.session_state["quick_error"])
    elif st.session_state.get("quick_result"):
        label, res = st.session_state["quick_result"]
        st.markdown(f"{ui.pill(res['decision'])} &nbsp; **{label}** - event #{res['event_id']}",
                    unsafe_allow_html=True)
        st.caption(res["reason"])

# ------------------------------------------------------------------ charts
c1, c2 = st.columns([3, 2])
with c1:
    ui.show_fig(viz.activity_timeline(events), key="ov_timeline")
with c2:
    ui.show_fig(viz.decision_breakdown(events), key="ov_donut")
c3, c4 = st.columns([3, 2])
with c3:
    ui.show_fig(viz.risk_distribution(events), key="ov_risk")

# ------------------------------------------------------------------ posture summary
with c4.container(border=True):
    st.markdown("**Campus security status (last 24 hours)**")
    if total:
        ts = pd.to_datetime(events["timestamp"])
        recent = events[ts >= datetime.now() - timedelta(hours=24)]
    else:
        recent = events
    if recent.empty:
        st.info("No requests in the last 24 hours. Use a quick action to generate activity.")
    else:
        share = float((recent["decision"] != "ALLOW").mean())
        posture = "Normal" if share < 0.25 else ("Elevated" if share < 0.5 else "High alert")
        st.metric("Posture", posture, f"{share:.0%} of {len(recent)} requests denied or flagged", delta_color="off")
    active_users = [u for u in users if u["active"]]
    rows = [
        ("Active devices not compliant", sum(1 for d in devices if d["active"] and d["compliance_status"] != "compliant")),
        ("Active users without verified identity", sum(1 for u in active_users if u["identity_status"] != "verified")),
        ("Deactivated accounts", len(users) - len(active_users)),
    ]
    show = pd.DataFrame(rows, columns=["Posture indicator", "Count"])
    ui.show_df(show)
    st.caption("Posture is a simple demo heuristic: share of denied + flagged requests (<25% normal, <50% elevated).")

# ------------------------------------------------------------------ recent events
st.subheader("Recent security events")
if events.empty:
    st.info("The audit log is empty. Run a scenario, submit a request, or use a quick action.")
else:
    recent_events = events.head(10)[["event_id", "timestamp", "user_id", "user_role", "device_id", "resource_id",
                                     "risk_score", "decision", "reason"]]
    ui.show_df(recent_events.rename(columns={
        "event_id": "Event", "timestamp": "Time", "user_id": "User", "user_role": "Role", "device_id": "Device",
        "resource_id": "Resource", "risk_score": "Risk", "decision": "Decision", "reason": "Reason"}))
