# Zero Trust Campus Network Simulator
### An Intelligent Simulation Platform for Identity-Based Access Control and AI-Powered Network Anomaly Detection

*Academic AI Project-Based Learning (PBL) report. Replace the placeholders (name, roll number, guide, date) before submission.*

## 1. Abstract
This project builds an interactive simulator of a university campus network that demonstrates Zero Trust security.
Simulated access requests pass through a modular decision pipeline: request validation, identity and device
verification, role-based least-privilege policy evaluation, contextual risk scoring and anomaly detection with an
Isolation Forest plus transparent rules. Each decision is recorded in a SQLite audit log, which feeds a Streamlit
dashboard. All data is synthetic and the system never touches a real network. Automated tests cover the policy,
risk, anomaly, persistence and export logic.

## 2. Introduction
Zero Trust replaces "trust everything inside the perimeter" with "never trust, always verify": every request is
authenticated, authorised and evaluated in context, whatever its network origin (NIST SP 800-207). Campuses are a good
case study: many unmanaged personal devices, mixed roles (students, faculty, administrators) and resources of very
different sensitivity (learning platform versus administrative records).

## 3. Existing system and its limitations
A typical campus relies on perimeter controls (firewall, campus Wi-Fi, VPN) and coarse network zones. Limitations:
implicit trust once inside; broad lateral movement after one compromised account or device; weak link between device
health and access; little contextual (time, behaviour) evaluation; limited per-request audit evidence; and few safe
tools for students to experiment with these ideas.

## 4. Proposed system
A simulator that enforces explicit, editable policies on every request, combines mandatory checks with risk and
anomaly signals under a fixed precedence, explains each decision in plain English and records it. It is an
educational model, not a security product.

## 5. Problem statement
Design and implement an educational platform that demonstrates identity-based, least-privilege access control and
AI-assisted anomaly detection on a simulated campus network, with transparent decisions and a persistent audit trail.

## 6. Objectives
(1) Policy engine with default deny. (2) Identity, device and role verification. (3) Deterministic risk scoring with
visible factors. (4) Isolation Forest with a rule-based fallback and honest evaluation on synthetic data. (5) Persistent,
searchable, exportable audit log. (6) Editable entities and policies whose changes affect later decisions.
(7) Tests and documentation suitable for a viva.

## 7. Requirements
**Functional.** FR1 submit simulated requests; FR2 evaluate mandatory checks; FR3 compute risk and explain factors;
FR4 detect anomalies; FR5 apply decision precedence; FR6 log every decision; FR7 filter, sort, inspect and export logs;
FR8 manage users, devices, resources and policies with validation; FR9 run predefined scenarios; FR10 show dashboards
computed from stored data.
**Non-functional.** NFR1 deterministic decisions for identical inputs and settings; NFR2 starts even if model training
fails; NFR3 parameterised SQL and validated inputs; NFR4 no internet or paid services needed; NFR5 modular code with
business logic outside the UI; NFR6 reproducible training (fixed seeds); NFR7 persistent storage across restarts.

## 8. System architecture
See `docs/architecture.md` for the Mermaid diagram and request flow. Layers: Streamlit pages -> decision pipeline ->
(policy engine, risk scorer, anomaly detector) -> SQLite store.

## 9. Module descriptions
| Module | Responsibility |
|---|---|
| `config.py` | Vocabularies, thresholds, paths, topology mapping |
| `data/synthetic.py` | Reproducible labelled behaviour datasets (5 anomaly types) |
| `data/seed.py` | Fictional campus (12 users, 12 devices, 6 resources, 9 policies) and 130 initial events produced by the real pipeline |
| `data/scenarios.py` | 12 predefined scenarios; random normal / suspicious request generator |
| `models/policy_engine.py` | Mandatory checks, policy selection, role x resource matrix |
| `models/risk.py` | Additive, capped, explainable risk score |
| `models/anomaly.py` | Pipeline (scaler + Isolation Forest), rules, evaluation, leakage check, fallback |
| `models/pipeline.py` | `evaluate_access` orchestration and `decide` precedence |
| `database/store.py` | SQLite schema, parameterised CRUD, event queries, settings |
| `utils/validation.py`, `export.py`, `visualization.py`, `ui.py` | Input validation, CSV export, charts, UI helpers |
| `pages/*` | Seven Streamlit pages |

## 10. Methodology
Iterative: design the data model and precedence rules first; implement pure-function core logic with tests; add the
persistence layer; build thin UI pages over the core; document. Requests are decided deterministically; randomness
only appears in synthetic data generation and is seeded.

## 11. Zero Trust principles and where they appear
| Principle | Implementation |
|---|---|
| Never trust by location | Network position is not an input; every path crosses the policy enforcement point |
| Verify identity explicitly | Account active and identity status `verified` are mandatory |
| Verify the device | Device active, compliant (per policy) and bound to the requesting user |
| Least privilege | Default deny; role must be listed on the resource and an enabled policy must grant category, sensitivity and request type |
| Use context | Business-hours conditions (mandatory) and risk factors (graduated) |
| Assume breach / monitor | Anomaly detection; every decision audited |

## 12. Machine-learning approach
**Task.** Unsupervised anomaly detection on one-user, ten-minute behaviour windows.
**Features (8).** requests per window, failed authentication count, access frequency, unusual-time flag, distinct
resources, device-compliance flag, failed-request ratio, request-frequency deviation.
**Model.** scikit-learn `Pipeline`: `StandardScaler` then `IsolationForest` (200 trees, `random_state` = 42,
`contamination` = training anomaly share). Training uses no labels.
**Explainability.** Isolation Forest does not provide reliable per-feature explanations, so the reasons shown come
from separate, readable threshold rules. The final anomaly flag is "model OR rules".
**Robustness.** Missing values are median-imputed, infinities removed, invalid inputs rejected, a minimum training size
is enforced, and training failure falls back to the rules with a visible warning.

## 13. Dataset generation
`data/synthetic.py` draws normal windows from Poisson, log-normal and Beta distributions chosen by the author, and
injects five anomaly types (burst, brute force, odd hours, resource sweep, noncompliant probe). Training set: 1,500
rows (5% anomalies, seed 42). Test set: 600 rows (12% anomalies, seed 1042), generated separately; a leakage check
raises an error if any feature row appears in both. Distributions are **not** calibrated on real traffic.

## 14. Testing strategy
pytest, with a temporary SQLite file per test. Areas: policy outcomes for allowed/denied/invalid-identity/inactive/
noncompliant/missing/unknown cases; policy, role, compliance and threshold edits changing later decisions; precedence
rules; deterministic risk scores and caps; anomaly validation, reproducibility, leakage and fallback; schema creation,
persistence across a simulated restart, idempotent seeding, audit records, SQL-injection resistance; filters and
sorting; CSV export correctness and formula-injection protection; form validators; all 12 scenarios end to end.

## 15. Results (only what was actually executed)
Executed in the build environment (Python 3.13.16, scikit-learn 1.9.1, pandas 3.0.5, numpy 2.5.3):

| Check | Observed result |
|---|---|
| `pytest` | **91 passed, 1 skipped** in about 29 s. The skipped file (`tests/test_ui_smoke.py`) needs the real `streamlit` package, which was not installable in the build environment |
| Scenario Lab, 12 scenarios | all 12 produced the expected decision |
| Seed data | 130 events: 78 ALLOW, 31 DENY, 21 FLAG (11 distinct users and devices appear in the log) |
| Isolation Forest on the 600-row synthetic test set | precision 0.972, recall 0.958, F1 0.965; confusion matrix [[526, 2], [3, 69]] |
| Recall by simulated type | brute force 1.00, noncompliant probe 1.00, burst 1.00, odd hours 1.00, resource sweep 0.79 |
| Transparent rules on the same test set | precision 1.00, recall 1.00 (expected: the rules were written knowing how the synthetic anomalies are built) |

**Interpretation.** These figures show the model separates *simulated* anomalies from *simulated* normal behaviour.
They are not evidence of real-world detection accuracy. Metrics may vary slightly with library versions.

**Not verified in the build environment:** the Streamlit/Plotly user interface was not rendered there. The page code
was exercised only with stand-in modules to check that it executes. Run `streamlit run app.py` and
`pytest` on your machine and record the outcome in the table below.

| UI check (fill in after running locally) | Result |
|---|---|
| App starts with `streamlit run app.py` | |
| All 7 pages load without errors | |
| `pytest` including `tests/test_ui_smoke.py` | |

## 16. Limitations
Synthetic data only; author-chosen risk weights and thresholds; single-user demo; no real authentication; the model
retrains at start-up; Isolation Forest is not explained natively; no real telemetry or network integration.

## 17. Future enhancements
Real log ingestion; time-series and sequence features; SHAP-style or surrogate-model explanations; policy versioning
and approvals; micro-segmentation modelling; user and entity behaviour baselines; dashboard login with roles.

## 18. Conclusion
The simulator demonstrates how explicit policy, device and identity verification, contextual risk and anomaly
detection combine into explainable access decisions with a complete audit trail, while being honest about what a
synthetic-data educational project can and cannot show.

## 19. References
1. S. Rose, O. Borchert, S. Mitchell, S. Connelly, *Zero Trust Architecture*, NIST Special Publication 800-207, 2020. https://csrc.nist.gov/pubs/sp/800/207/final
2. CISA, *Zero Trust Maturity Model*. https://www.cisa.gov/zero-trust-maturity-model
3. scikit-learn documentation, `IsolationForest`. https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
4. scikit-learn User Guide, *Novelty and Outlier Detection*. https://scikit-learn.org/stable/modules/outlier_detection.html
5. F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation Forest", *IEEE ICDM*, 2008.
6. Streamlit documentation. https://docs.streamlit.io

*(Please open each link before submission to confirm it is still current.)*
