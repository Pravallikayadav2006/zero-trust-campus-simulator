"""Streamlit helpers shared by every page (styling, cached runtime, result renderer)."""
from __future__ import annotations

import pandas as pd
import streamlit as st

import config
from data.seed import bootstrap

STATUS_ICON = {"pass": "✅ pass", "fail": "❌ fail", "skipped": "⏭ skipped"}
DECISION_TEXT = {"ALLOW": "✓ ALLOWED", "DENY": "✕ DENIED", "FLAG": "⚑ FLAGGED"}

CSS = """
<style>
.block-container {padding-top: 2rem; max-width: 1400px;}
div[data-testid="stMetric"] {background:#111a2e; border:1px solid #1f2d4a; border-radius:10px; padding:12px 16px;}
div[data-testid="stMetricLabel"] p {color:#8a99b3; font-size:0.85rem;}
.pill {display:inline-block; padding:3px 12px; border-radius:999px; font-weight:700; font-size:0.9rem;
       letter-spacing:0.03em; border:1px solid;}
.pill-allow {color:#34d399; background:rgba(52,211,153,0.12); border-color:#34d399;}
.pill-deny  {color:#f87171; background:rgba(248,113,113,0.12); border-color:#f87171;}
.pill-flag  {color:#fbbf24; background:rgba(251,191,36,0.12); border-color:#fbbf24;}
.zt-brand {font-weight:700; font-size:1.05rem; color:#e6edf7; margin-bottom:0.2rem;}
.zt-sub {color:#8a99b3; font-size:0.78rem; line-height:1.3;}
.zt-disclaimer {border:1px solid #fbbf24; background:rgba(251,191,36,0.08); color:#e6edf7; border-radius:8px;
                padding:8px 12px; font-size:0.82rem;}
</style>
"""


@st.cache_resource(show_spinner="Training the anomaly model and preparing the demo campus...")
def get_runtime():
    """(Database, AnomalyDetector). Cached so Streamlit reruns never re-seed or re-train."""
    return bootstrap()


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def disclaimer() -> None:
    st.markdown(f'<div class="zt-disclaimer"><b>Educational simulation.</b> {config.DISCLAIMER}</div>',
                unsafe_allow_html=True)


def pill(decision: str) -> str:
    return f'<span class="pill pill-{decision.lower()}">{DECISION_TEXT.get(decision, decision)}</span>'


def show_df(df: pd.DataFrame, **kwargs) -> None:
    """st.dataframe that works on old (use_container_width) and new (width='stretch') Streamlit."""
    kwargs.setdefault("hide_index", True)
    try:
        st.dataframe(df, width="stretch", **kwargs)
    except TypeError:
        st.dataframe(df, use_container_width=True, **kwargs)


def show_fig(fig, key: str | None = None) -> None:
    try:
        st.plotly_chart(fig, width="stretch", key=key)
    except TypeError:
        st.plotly_chart(fig, use_container_width=True, key=key)


def checks_frame(checks: list[dict]) -> pd.DataFrame:
    return pd.DataFrame([
        {"Check": c["label"], "Result": STATUS_ICON.get(c["status"], c["status"]), "Detail": c["detail"]}
        for c in checks
    ])


def user_label(u: dict) -> str:
    return f"{u['user_id']} - {u['display_name']} ({u['role']}){'' if u['active'] else ' [inactive]'}"


def device_label(d: dict) -> str:
    return f"{d['device_id']} - {d['device_type']}, owner {d['owner_id']}{'' if d['active'] else ' [inactive]'}"


def resource_label(r: dict) -> str:
    return f"{r['resource_id']} - {r['name']} ({r['category']}, sensitivity {r['sensitivity']})"


def render_result(result: dict, key_prefix: str = "res") -> None:
    """Show all ten required items of one access decision. Shared by the simulator and the Scenario Lab."""
    decision = result["decision"]
    box = {"ALLOW": st.success, "FLAG": st.warning, "DENY": st.error}[decision]
    st.markdown(pill(decision), unsafe_allow_html=True)
    box(result["reason"])

    user, device, resource = result["user"], result["device"], result["resource"]
    req = result["request"]
    c1, c2, c3 = st.columns(3)
    with c1.container(border=True):
        st.markdown("**1-2. User identity and role**")
        if user:
            st.write(f"{user['display_name']} (`{user['user_id']}`)")
            st.write(f"Role: **{user['role']}**  \nIdentity: **{user['identity_status']}**  \n"
                     f"Account: **{'active' if user['active'] else 'inactive'}**")
        else:
            st.write(f"`{req['user_id'] or '-'}` - not found")
    with c2.container(border=True):
        st.markdown("**3-4. Device and trust status**")
        if device:
            st.write(f"`{device['device_id']}` ({device['device_type']})")
            st.write(f"Compliance: **{device['compliance_status']}**  \nLast verified: **{device['last_verified']}**  \n"
                     f"Owner: `{device['owner_id']}`")
        else:
            st.write(f"`{req['device_id'] or '-'}` - not found")
    with c3.container(border=True):
        st.markdown("**5-6. Resource and applicable policy**")
        if resource:
            st.write(f"{resource['name']} (`{resource['resource_id']}`)  \n{resource['category']} - "
                     f"{config.SENSITIVITY_LEVELS.get(resource['sensitivity'])} sensitivity  \n"
                     f"Request type: **{req['request_type']}**")
        else:
            st.write(f"`{req['resource_id'] or '-'}` - not found")
        st.write(f"Policy: **{result['policy_id'] or 'none (default deny)'}**")

    st.markdown("**7. Individual verification results** (all mandatory)")
    show_df(checks_frame(result["policy_checks"]))

    risk, anomaly = result["risk"], result["anomaly"]
    r_col, a_col = st.columns(2)
    with r_col.container(border=True):
        st.markdown("**8. Risk score and contributing factors**")
        if risk:
            m1, m2 = st.columns(2)
            m1.metric("Risk score", f"{risk['score']:g} / 100")
            m2.metric("Risk level", risk["level"])
            if risk["factors"]:
                show_df(pd.DataFrame(risk["factors"]).rename(
                    columns={"factor": "Factor", "points": "Points", "detail": "Detail"}))
            else:
                st.caption("No risk factors contributed.")
            t = result["thresholds"]
            st.caption(f"Flag at {t['risk_flag_threshold']:g}, deny at {t['risk_deny_threshold']:g}.")
        else:
            st.caption("Not calculated (the request was malformed).")
    with a_col.container(border=True):
        st.markdown("**Anomaly detection result**")
        if anomaly:
            label = "Anomaly detected" if anomaly["detected"] else "No anomaly detected"
            st.metric("Indicator (0-100)", f"{anomaly['score']:g}", label, delta_color="off")
            st.caption(f"Method: {anomaly['method'].replace('_', ' ')}; transparent rule score {anomaly['rule_score']}")
            if anomaly["reasons"]:
                show_df(pd.DataFrame(anomaly["reasons"])[["feature", "value", "rule"]].rename(
                    columns={"feature": "Feature", "value": "Value", "rule": "Triggered rule"}))
        else:
            st.caption("Not evaluated (the request was malformed).")

    st.caption(f"**9-10. Final decision:** {decision} - rule applied: `{result['decision_rule']}`. "
               + (f"Saved to the audit log as event #{result['event_id']}." if result.get("event_id")
                  else "Not saved to the audit log."))
