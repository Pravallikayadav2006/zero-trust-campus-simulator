# Zero Trust Campus Network Simulator

*An Intelligent Simulation Platform for Identity-Based Access Control and AI-Powered Network Anomaly Detection*

> **Educational simulation only.** Every user, device, resource and event is fictional and synthetic. The
> application never connects to, scans or modifies a real network, and it is **not production-ready**.

## 1. Introduction
An interactive Streamlit dashboard that models a university campus network and shows, request by request, how a
**Zero Trust** security model decides who may reach what: identity checks, device compliance, role-based and
least-privilege policies, contextual risk scoring, machine-learning anomaly detection and a persistent audit trail.

## 2. Problem statement
Traditional campus networks trust anyone who is "inside" (on campus Wi-Fi, in a lab, behind the firewall). A stolen
password or an infected laptop then gets broad access. Students learning security rarely get a safe place to *see*
how "never trust, always verify" works and how policy, risk and AI signals combine into a decision.

## 3. Objectives
1. Simulate campus access requests and decide them with a transparent, deterministic policy engine.
2. Demonstrate Zero Trust principles: verify identity, verify device, least privilege, assume breach, log everything.
3. Add an Isolation Forest anomaly detector with an explainable rule-based companion and a safe fallback.
4. Record every decision in a persistent SQLite audit log that can be searched and exported.
5. Make policies and entities editable so the effect of a change is immediately visible.

## 4. Features (all functional)
| Page | What it does |
|---|---|
| Executive Overview | Metrics, activity timeline, decision donut, risk histogram, posture summary, quick "normal / suspicious" actions - all computed from stored events |
| Campus Network Simulator | Topology diagram; pick user, device, resource and request type; full 10-point decision breakdown with the request path highlighted |
| Zero Trust Policy Engine | Role x resource matrix, editable policies, risk thresholds, precedence rules, live example scenarios A-E |
| AI Anomaly Detection | Isolation Forest training status, evaluation on a separate labelled synthetic test set (precision, recall, F1, confusion matrix), live scoring, dataset download |
| Scenario Lab | 12 predefined scenarios (the 10 required + 2 extra), "Run all", expected-vs-actual, policy-vs-anomaly comparison |
| Security Event Logs | Filter by date/role/resource/type/decision, search, sort, event details, validated CSV export, guarded clearing |
| Users, Devices & Resources | Validated add / edit / deactivate forms; changes affect the next request |

## 5. Architecture
```
Streamlit pages (UI only)  ->  models/pipeline.py  ->  models/policy_engine.py   (mandatory checks)
                                                  ->  models/risk.py            (risk score + factors)
                                                  ->  models/anomaly.py         (Isolation Forest + rules)
                                                  ->  database/store.py         (SQLite audit log, entities)
```
Business logic lives outside the UI; pages never duplicate it. See `docs/architecture.md` for a Mermaid diagram.

**Decision precedence:** R1 any mandatory check fails -> DENY (risk/anomaly ignored) | R2 risk >= deny threshold -> DENY |
R3 risk >= flag threshold or anomaly -> FLAG (permitted but flagged for review) | R4 otherwise -> ALLOW.
A "normal" anomaly result or a low risk score can never grant access.

## 6. Technology stack
Python 3.11+ (developed and tested on 3.13), Streamlit, Pandas, NumPy, scikit-learn, Plotly, NetworkX, SQLite
(standard library), pytest. No paid APIs, no keys, no internet needed after installation.

## 7. Installation
```bash
cd zero-trust-campus-simulator
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

## 8. Run
```bash
streamlit run app.py
```
Open the address Streamlit prints (usually http://localhost:8501). The first start trains the model (about a
second) and creates `runtime/zt_campus.db` with fictional demo data and 130 synthetic events. Later starts reuse it.

Run the automated tests:
```bash
pytest
```

## 9. Directory structure
```
app.py                 entry point, navigation, sidebar, system information
config.py              constants, vocabularies, default thresholds
data/        seed.py (demo campus + events), synthetic.py (ML datasets), scenarios.py (scenarios, quick actions)
models/      pipeline.py, policy_engine.py, risk.py, anomaly.py
database/    store.py (SQLite)
pages/       page_overview / network / policy / anomaly / scenarios / logs / entities
utils/       validation.py, export.py (CSV), visualization.py (Plotly/NetworkX), ui.py (Streamlit helpers)
tests/       pytest suite
docs/        project_report.md, architecture.md, viva_questions.md, presentation_outline.md, demo_guide.md
runtime/     SQLite database is created here
.streamlit/  dark navy theme
```

## 10. Sample usage
1. **Overview** - note the totals; press *Generate suspicious activity* and watch Flagged/Denied change.
2. **Campus Network Simulator** - user `U-S01`, device `D-S01L`, resource `R-LMS`, `read` -> ALLOW.
   Change the resource to `R-ADM` and request type `manage` -> DENY (least privilege).
3. **Policy Engine** - edit policy `P-01` and remove `read`; repeat step 2's first request -> DENY. Restore it.
4. **Scenario Lab** - press *Run all*; compare the policy and anomaly columns.
5. **Security Event Logs** - filter `Decision = DENY`, open an event, export CSV.
Full presentation script: `docs/demo_guide.md`.

## 11. Troubleshooting
| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | Activate the virtual environment and run `pip install -r requirements.txt` |
| `streamlit: command not found` | Use `python -m streamlit run app.py` |
| Page shows a deprecation warning about `use_container_width` | Harmless; the helpers in `utils/ui.py` adapt to your Streamlit version |
| Want a clean start | Stop the app and delete `runtime/zt_campus.db`; it is recreated on next start |
| Port already in use | `streamlit run app.py --server.port 8502` |
| Sidebar says "rule-based fallback" | Model training failed; the message states why. The app keeps working on transparent rules |

## 12. Limitations and future scope
- All data is synthetic; ML metrics show separation of *simulated* anomalies only, not real-world accuracy.
- Isolation Forest gives no reliable per-feature explanation; the "why" comes from separate transparent rules.
- Single-user demo: no real authentication, no concurrency control beyond SQLite's own, shared model object.
- Risk weights and thresholds are author-chosen, not calibrated on real traffic.
- The model retrains at start-up rather than loading a saved file (deliberate: avoids unsafe pickle loading).
- Future: real log ingestion, time-series features, SHAP-style explanations, micro-segmentation rules, policy
  versioning and approval workflow, role-based access to the dashboard itself.
