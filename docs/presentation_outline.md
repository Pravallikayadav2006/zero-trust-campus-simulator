# Presentation outline (12 slides, about 10 minutes + demo)

**Slide 1 - Title.** Zero Trust Campus Network Simulator; subtitle; your name, roll number, guide, date.
Say: "A safe, simulated way to see Zero Trust decisions."

**Slide 2 - Problem statement.** Campus networks trust anyone "inside". One stolen password or non-compliant laptop can
reach sensitive systems. Students lack a safe lab to see how policy, risk and AI combine.

**Slide 3 - Motivation.** Mixed roles and many personal devices; sensitive records beside public resources;
Zero Trust is widely recommended (NIST SP 800-207); learning by simulation avoids touching a real network.

**Slide 4 - Existing system.** Perimeter firewall / VPN / coarse zones; implicit trust; weak device-health link; little
context; limited audit evidence.

**Slide 5 - Proposed system.** Per-request verification: identity, device, role policy, risk, anomaly - then
ALLOW / FLAG / DENY with a plain-English reason and an audit record. Everything is simulated.

**Slide 6 - Architecture.** Paste the Mermaid diagram from `docs/architecture.md` as a picture. Pages -> pipeline ->
policy engine / risk / anomaly -> SQLite. Business logic is outside the UI.

**Slide 7 - Technology stack.** Python, Streamlit, Pandas/NumPy, scikit-learn, Plotly, NetworkX, SQLite, pytest.
Free, offline, no API keys.

**Slide 8 - Implementation.** Seven pages; decision precedence R1-R4 (a failed mandatory check always denies);
editable policies and entities; 12 scenarios; CSV export; idempotent seeding.

**Slide 9 - AI model.** Isolation Forest (unsupervised) in a scaler pipeline; 8 behaviour features; synthetic train and
separate labelled test sets; transparent rules explain alerts; rule-based fallback if training fails. Say clearly:
Isolation Forest is not natively explainable.

**Slide 10 - Results and demo.** Executed results: 91 automated tests passed; 12 of 12 scenarios as expected; on the
synthetic test set precision 0.972 / recall 0.958 / F1 0.965 (confusion matrix [[526, 2], [3, 69]]). Add a
disclaimer: synthetic data, not real-world accuracy. Then run the demo from `docs/demo_guide.md`.
(If you re-run on your machine, quote your own numbers.)

**Slide 11 - Limitations and future scope.** Synthetic data; author-chosen weights; single-user demo; retrain at start.
Future: real log ingestion, time-series features, SHAP-style explanations, policy versioning, dashboard login.

**Slide 12 - Conclusion.** Zero Trust decisions made visible and explainable; policy first, AI as an extra signal;
every decision audited; honest about limits. "Thank you - questions?"
