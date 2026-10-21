"""Page 5 - Scenario Lab: predefined simulations, policy-vs-anomaly comparison, Run All."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from data.scenarios import SCENARIOS  # noqa: E402
from models.pipeline import evaluate_access  # noqa: E402
from utils import ui  # noqa: E402

db, detector = ui.get_runtime()
by_id = {s["id"]: s for s in SCENARIOS}


def run(scenarios: list[dict]) -> None:
    save = st.session_state.get("sc_save", True)
    out = []
    for s in scenarios:
        res = evaluate_access(db, detector, s["request"], s["context"], event_type="scenario_lab", persist=save)
        out.append({"scenario": s, "result": res})
    st.session_state["sc_results"] = out


st.title("Scenario Lab")
st.caption("Run predefined, harmless simulations. Each scenario shows its inputs, the policy checks, the anomaly "
           "result and the final decision. Nothing interacts with a real system.")

top = st.columns([3, 1, 1, 2])
chosen = top[0].selectbox("Scenario", list(by_id), format_func=lambda i: f"{i}. {by_id[i]['name']}",
                          label_visibility="collapsed")
top[1].button("Run selected", on_click=run, args=([by_id[chosen]],), type="primary")
top[2].button("Run all", on_click=run, args=(SCENARIOS,))
top[3].checkbox("Save results to the audit log", True, key="sc_save")
st.caption(by_id[chosen]["description"])

results = st.session_state.get("sc_results")
if not results:
    st.info("Choose a scenario and press **Run selected**, or press **Run all** to execute every scenario.")
    st.stop()

rows = []
for item in results:
    s, r = item["scenario"], item["result"]
    rows.append({
        "#": s["id"], "Scenario": s["name"], "Policy engine": r["policy_verdict"],
        "Anomaly detector": r["anomaly_verdict"], "Risk": None if r["risk"] is None else r["risk"]["score"],
        "Final decision": r["decision"], "Expected": s["expected"],
        "Matches expected": "yes" if r["decision"] == s["expected"] else "NO", "Reason": r["reason"],
    })
table = pd.DataFrame(rows)
matches = int((table["Matches expected"] == "yes").sum())

tab_res, tab_cmp, tab_detail = st.tabs(["Results table", "Policy vs anomaly detector", "Scenario details"])

with tab_res:
    (st.success if matches == len(table) else st.warning)(
        f"{matches} of {len(table)} executed scenario(s) produced the expected decision "
        "(with the current policies and entities; edits on other pages can legitimately change outcomes).")
    ui.show_df(table)
    st.download_button("Download results (CSV)", table.to_csv(index=False), file_name="scenario_results.csv",
                       mime="text/csv")

with tab_cmp:
    st.markdown("The **policy engine** (mandatory checks) and the **anomaly detector** judge the same request "
                "independently. The final decision combines them with a fixed precedence.")
    cmp = table[["#", "Scenario", "Policy engine", "Anomaly detector", "Final decision"]].copy()
    cmp["Policy engine"] = cmp["Policy engine"].map({"PASS": "PASS - mandatory checks satisfied",
                                                    "FAIL": "FAIL - mandatory check failed"})
    cmp["Anomaly detector"] = cmp["Anomaly detector"].map({"NORMAL": "Normal", "ANOMALY": "Anomaly detected",
                                                          "n/a": "not evaluated"})
    ui.show_df(cmp)
    ui.show_df(pd.DataFrame({
        "Policy engine": ["FAIL", "FAIL", "PASS", "PASS"],
        "Anomaly detector": ["Normal", "Anomaly", "Anomaly", "Normal"],
        "Final decision": ["DENY (R1)", "DENY (R1)", "FLAG (R3), or DENY if risk >= deny threshold (R2)",
                           "ALLOW (R4), unless risk >= flag threshold"],
    }))
    st.caption("A 'Normal' anomaly result never rescues a failed policy check (first two rows).")

with tab_detail:
    for item in results:
        s, r = item["scenario"], item["result"]
        with st.expander(f"{s['id']}. {s['name']} - {r['decision']}"):
            st.write(s["description"])
            st.markdown("**Inputs**")
            st.json({"request": s["request"], "context": r["context"] or s["context"]}, expanded=False)
            ui.render_result(r, key_prefix=f"sc{s['id']}")
