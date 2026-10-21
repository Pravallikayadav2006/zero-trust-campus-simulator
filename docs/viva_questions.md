# Viva questions and answers

## Zero Trust
**1. What is Zero Trust?** A security model that never trusts a request just because of where it comes from. Every
request is verified (identity, device, context) and authorised with least privilege - "never trust, always verify".

**2. How is it different from perimeter security?** Perimeter security trusts everything inside the firewall. Zero
Trust treats the inside like the outside, so one stolen account or infected laptop cannot roam freely.

**3. Where does the project show "never trust by location"?** Network position is not an input to any check, and the
topology has no direct path to a resource: traffic always goes gateway -> policy enforcement point -> resource.

**4. What does "assume breach" mean?** Design as if an attacker may already be inside, so you limit access, monitor
behaviour and log everything. The anomaly detector and audit log serve this idea.

**5. What is a Policy Enforcement Point (PEP)?** The component that stops or lets through each request after the
policy decision. In the simulator, `evaluate_access` decides and the topology draws the PEP node where denied requests stop.

## Least privilege, RBAC, verification
**6. What is least privilege?** Give each user only the access they need. Here: default deny, and access needs a role
listed on the resource plus an enabled policy that grants the category, sensitivity and request type.

**7. What is RBAC?** Role-Based Access Control: permissions attach to roles (student, faculty, admin), and users get
permissions through their role.

**8. Why have both resource "allowed roles" and policies?** They are two independent gates. Both must allow the
request, which is stricter and easier to audit than either alone.

**9. How is identity verified in the simulator?** The user must exist, the account must be active and the identity
status must be `verified`. No passwords are stored; verification status is simulated data.

**10. How is the device verified?** The device must exist, be active, be compliant (if the policy requires it) and be
registered to the same user making the request.

**11. What happens if a user's role is changed?** The next request uses the new role, so decisions change immediately
(tested in `test_role_change_affects_subsequent_decisions`).

**12. What is "default deny"?** If no enabled policy explicitly grants access, the request is denied.

## Policy enforcement and precedence
**13. What is the order of precedence?** R1 failed mandatory check -> DENY; R2 risk >= deny threshold -> DENY;
R3 risk >= flag threshold or anomaly -> FLAG; R4 otherwise ALLOW.

**14. Can a low risk score or a "normal" anomaly result grant access?** No. ALLOW is only reachable after every
mandatory check passes; R1 is evaluated first.

**15. Difference between a mandatory check and a risk factor?** A mandatory check is pass/fail and any failure denies.
A risk factor adds points to a score that triggers flagging or denial only after mandatory checks pass.

**16. What does FLAG mean?** The request is permitted by policy but flagged for analyst review because risk is
elevated or an anomaly was detected. It is "suspicious simulated activity", not a confirmed attack.

**17. Why are decisions deterministic?** The pipeline uses plain functions of the request, entities, policies and
thresholds; there is no randomness at decision time.

## Risk scoring
**18. How is the risk score computed?** Additive factors: failed sign-ins (6 each, max 30), unusual hour (+15),
request-rate deviation (up to 20), resource spread (up to 15), failed-request ratio (up to 15), resource sensitivity
(0-9), stale device verification (5-10). Capped at 100; each factor is shown to the user.

**19. Where do the weights come from?** The project author chose them. They are not calibrated on real data, which is a
stated limitation.

**20. Why show factors instead of just a number?** Explainability: users and auditors can see why a request scored high.

## Machine learning
**21. What is anomaly detection?** Finding observations that differ from the usual pattern, often without labels.

**22. How does an Isolation Forest work?** It builds many random trees that split the data randomly. Unusual points are
easier to isolate, so they end up with shorter paths and get higher anomaly scores.

**23. Why Isolation Forest here?** It works without labels, handles numeric features well, is fast and is available in
scikit-learn.

**24. Is the model supervised?** No. It trains without labels; labels in the test set are used only to evaluate.

**25. Why scale features first?** A `StandardScaler` puts features on comparable scales; the same pipeline object is
used for training and inference so they stay consistent.

**26. What is `contamination`?** The expected share of anomalies in the training data; it sets the score threshold.
We set it to the known synthetic training share (5%).

**27. Can Isolation Forest explain which feature caused an alert?** Not reliably. So the project shows separate,
transparent threshold rules as the explanation and says so on the page.

**28. What is the rule-based fallback?** If training fails, the app uses the threshold rules and shows a warning, so it
never crashes.

**29. How do you prevent training/test leakage?** The two sets use different seeds and a check raises an error if any
feature row appears in both; the test set is never used to fit the model.

**30. How are missing or invalid values handled?** Missing/infinite values are replaced with training medians;
wrong types, negatives, out-of-range ratios or non-binary flags are rejected with a clear error.

## Evaluation metrics and synthetic data
**31. Define precision, recall and F1.** Precision = flagged items that were truly anomalies. Recall = anomalies that
were found. F1 = harmonic mean of the two.

**32. What is a confusion matrix?** A 2x2 table of true/false positives/negatives. Ours (synthetic test set) was
[[526, 2], [3, 69]] in the executed run.

**33. Why use synthetic data?** There is no permission or safe way to use real campus traffic; synthetic data is
reproducible, labelled and fictional.

**34. Do the metrics prove it works on a real network?** No. They only show the model separates *simulated* anomalies
from *simulated* normal behaviour; real traffic would differ.

**35. Why do the rules score 100% on the test set?** The rules were written with knowledge of how the synthetic anomalies
are built, so this is expected and not meaningful for real data.

**36. Why did the Isolation Forest do worse on "resource sweep"?** Those windows overlap more with normal behaviour in
the other features (recall 0.79 in the executed run), which is why the final flag also uses the transparent rules.

## SQLite, Streamlit, audit logging
**37. Why SQLite?** It is built into Python, needs no server, stores data in one file and supports transactions.

**38. How do you prevent SQL injection?** Parameterised queries, whitelisted table and column names, and a test that
a malicious search string returns nothing and damages nothing.

**39. What does the audit log record?** Event ID, timestamp, user, role, device, resource, request type, policy
checks, risk score and factors, anomaly result, final decision, reason and a "simulated" flag.

**40. Why log denied requests?** Denials are the most useful security evidence, and Zero Trust requires every decision
to be recorded.

**41. How do you avoid duplicate demo data on Streamlit reruns?** Seeding is idempotent: `INSERT OR IGNORE` for
entities and a `demo_seeded` flag written in the same transaction as the demo events. The runtime is cached with
`st.cache_resource`.

**42. What is Streamlit?** A Python framework that turns scripts into web apps; the script reruns on each interaction,
and `st.session_state` keeps values between reruns.

**43. Why separate business logic from the pages?** Testability and reuse: pages only collect input and display
results; the pipeline can be tested without a browser.

## Limitations
**44. What are the main limitations?** Synthetic data, author-chosen weights, simulated verification, single-user
demo, retrain-on-start model, no real telemetry.

**45. How would you extend it?** Ingest real logs (with permission), add time-series features, use SHAP-style
explanations, add policy versioning and dashboard authentication.

**46. Is this production-ready?** No. It is an educational simulator and says so in the interface.
