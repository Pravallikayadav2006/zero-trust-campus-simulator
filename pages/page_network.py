"""Page 2 - Campus Network Simulator: pick user, device, resource and submit a simulated request."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st  # noqa: E402

import config  # noqa: E402
from models.pipeline import evaluate_access  # noqa: E402
from utils import ui, visualization as viz  # noqa: E402

db, detector = ui.get_runtime()

users = {u["user_id"]: u for u in db.list_entities("users")}
devices = {d["device_id"]: d for d in db.list_entities("devices")}
resources = {r["resource_id"]: r for r in db.list_entities("resources")}

CTX_DEFAULTS = {
    "ns_failed": config.DEFAULT_CONTEXT["failed_auth_count"],
    "ns_rpw": config.DEFAULT_CONTEXT["requests_per_window"],
    "ns_freq": config.DEFAULT_CONTEXT["access_frequency"],
    "ns_distinct": config.DEFAULT_CONTEXT["distinct_resources"],
    "ns_ratio": config.DEFAULT_CONTEXT["failed_request_ratio"],
    "ns_use_now": True,
    "ns_hour": 11,
    "ns_rtype": "read",
}


def owned_device(user_id: str):
    return next((d for d, dev in devices.items() if dev["owner_id"] == user_id), next(iter(devices)))


def sync_device() -> None:
    """When the user changes, preselect that user's own device (it can still be changed manually)."""
    st.session_state["ns_device"] = owned_device(st.session_state["ns_user"])


def reset_form() -> None:
    """Reset the form and the displayed result. The persistent audit log is NOT touched."""
    for key, value in CTX_DEFAULTS.items():
        st.session_state[key] = value
    first_user = next(iter(users))
    st.session_state["ns_user"] = first_user
    st.session_state["ns_device"] = owned_device(first_user)
    st.session_state["ns_resource"] = next(iter(resources))
    st.session_state.pop("ns_result", None)


for key, value in CTX_DEFAULTS.items():
    st.session_state.setdefault(key, value)
st.session_state.setdefault("ns_user", next(iter(users)))
st.session_state.setdefault("ns_device", owned_device(st.session_state["ns_user"]))
st.session_state.setdefault("ns_resource", next(iter(resources)))

st.title("Campus Network Simulator")
st.caption("Choose who is asking, from which device, for which resource. Every request is evaluated by the "
           "Zero Trust pipeline and recorded in the audit log. Nothing here touches a real network.")

left, right = st.columns([3, 2])

with right:
    with st.container(border=True):
        st.markdown("**Simulated access request**")
        st.selectbox("User", list(users), key="ns_user", format_func=lambda i: ui.user_label(users[i]),
                     on_change=sync_device)
        st.selectbox("Device", list(devices), key="ns_device", format_func=lambda i: ui.device_label(devices[i]),
                     help="Pick a device owned by someone else to see the device-binding check fail.")
        st.selectbox("Destination resource", list(resources), key="ns_resource",
                     format_func=lambda i: ui.resource_label(resources[i]))
        st.selectbox("Request type", config.REQUEST_TYPES, key="ns_rtype")
        with st.expander("Behavioural context (advanced)"):
            st.checkbox("Use the current time of day", key="ns_use_now")
            st.slider("Hour of day", 0, 23, key="ns_hour", disabled=st.session_state["ns_use_now"])
            st.number_input("Failed authentication attempts", 0, 50, key="ns_failed")
            st.number_input("Requests in this 10-minute window", 0, 500, key="ns_rpw")
            st.number_input("Usual accesses per hour (24 h average)", 0.0, 1000.0, step=1.0, key="ns_freq")
            st.number_input("Distinct resources requested", 0, 50, key="ns_distinct")
            st.slider("Share of requests that failed", 0.0, 1.0, step=0.05, key="ns_ratio")
        submit = st.button("Submit access request", type="primary")
        st.button("Reset simulation form", on_click=reset_form,
                  help="Clears this form and the result shown below. The saved audit history is not erased.")

if submit:
    context = {
        "hour": None if st.session_state["ns_use_now"] else int(st.session_state["ns_hour"]),
        "failed_auth_count": int(st.session_state["ns_failed"]),
        "requests_per_window": int(st.session_state["ns_rpw"]),
        "access_frequency": float(st.session_state["ns_freq"]),
        "distinct_resources": int(st.session_state["ns_distinct"]),
        "failed_request_ratio": float(st.session_state["ns_ratio"]),
    }
    request = {"user_id": st.session_state["ns_user"], "device_id": st.session_state["ns_device"],
               "resource_id": st.session_state["ns_resource"], "request_type": st.session_state["ns_rtype"]}
    try:
        st.session_state["ns_result"] = evaluate_access(db, detector, request, context, event_type="interactive")
    except Exception as exc:  # noqa: BLE001 - shown to the user; full traceback goes to the server log
        st.session_state.pop("ns_result", None)
        st.error(f"The simulation could not be completed: {exc}")
        raise

result = st.session_state.get("ns_result")
with left:
    ui.show_fig(viz.topology_figure(result["path"] if result else None, result["decision"] if result else None),
                key="ns_topology")
    if result:
        st.caption("Highlighted path: device group -> gateway -> policy enforcement point"
                   + (" -> resource." if result["path"]["reached_target"]
                      else ". The request stopped at the enforcement point and never reached the resource."))
    else:
        st.info("Submit a request to see its path through the network and the full decision.")

if result:
    st.divider()
    st.subheader("Decision")
    ui.render_result(result, key_prefix="ns")
