"""Zero Trust Campus Network Simulator - entry point.

Run with:  streamlit run app.py
EDUCATIONAL SIMULATION ONLY - never connects to a real network.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import streamlit as st  # noqa: E402

import config  # noqa: E402
from utils import ui  # noqa: E402

st.set_page_config(page_title=config.APP_TITLE, page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
ui.inject_css()
db, detector = ui.get_runtime()

PAGES = [
    st.Page("pages/page_overview.py", title="Executive Overview", icon=":material/dashboard:", default=True),
    st.Page("pages/page_network.py", title="Campus Network Simulator", icon=":material/hub:"),
    st.Page("pages/page_policy.py", title="Zero Trust Policy Engine", icon=":material/policy:"),
    st.Page("pages/page_anomaly.py", title="AI Anomaly Detection", icon=":material/psychology:"),
    st.Page("pages/page_scenarios.py", title="Scenario Lab", icon=":material/science:"),
    st.Page("pages/page_logs.py", title="Security Event Logs", icon=":material/receipt_long:"),
    st.Page("pages/page_entities.py", title="Users, Devices & Resources", icon=":material/groups:"),
]
page = st.navigation(PAGES)

with st.sidebar:
    st.markdown(f'<div class="zt-brand">🛡️ Zero Trust Campus</div><div class="zt-sub">{config.APP_SUBTITLE}</div>',
                unsafe_allow_html=True)
    st.write("")
    ui.disclaimer()
    with st.expander("System information"):
        status = detector.status()
        st.write(f"**Anomaly method:** {status['method'].replace('_', ' ')}")
        if status["warning"]:
            st.warning(status["warning"])
        st.write(f"**Training data:** {status['train_rows']} synthetic rows (seed {status['seed']})")
        st.write(f"**Test data:** {status['test_rows']} separate synthetic labelled rows")
        st.write(f"**Audit events stored:** {db.count_events()}")
        st.caption(f"Database file: `{db.path.name}` (SQLite, in the project's runtime folder). "
                   "All entities and events are fictional.")

page.run()
