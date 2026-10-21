# Demo guide (about 8 minutes)

Start: `streamlit run app.py`. Keep the sidebar disclaimer visible and say once that everything is simulated.

| # | Page | Do this | What to say |
|---|---|---|---|
| 1 | Executive Overview | Point at the four request metrics, then the "unique users / devices" row | "130 requests come from only a handful of users, so requests are not users." |
| 2 | Executive Overview | Click *Generate suspicious activity* twice | "Each click runs the real pipeline and writes an audit event; the counters change because they are computed from the log." |
| 3 | Network Simulator | `U-S01` / `D-S01L` / `R-LMS` / read -> Submit | "Allowed: identity verified, device compliant, policy P-01 grants it, risk is low." Show the highlighted path. |
| 4 | Network Simulator | Change resource to `R-ADM`, type `manage` -> Submit | "Denied by least privilege. The request stops at the policy enforcement point and never reaches the server." |
| 5 | Network Simulator | User `U-S03` (noncompliant phone) -> `R-LMS` | "The identity is fine but the device is not, so it is denied." |
| 6 | Network Simulator | Open *Behavioural context*, set failed sign-ins 6, failed ratio 0.5, 8 requests | "Policy passes, anomaly detected, so FLAGGED - permitted but suspicious simulated activity." |
| 7 | Policy Engine | Edit `P-01`, remove `read`, save; repeat step 3 | "Policy edits change the very next decision." Restore it afterwards. |
| 8 | Policy Engine | Risk handling: set deny threshold to 40, repeat step 6 | "Same behaviour, now DENY: risk handling is configurable but only after mandatory checks pass." Restore to 70. |
| 9 | AI Anomaly Detection | Show metrics, confusion matrix, then the synthetic-data warning | "High scores here only mean the model separates my simulated anomalies. It proves nothing about a real network." |
| 10 | Scenario Lab | *Run all*, open *Policy vs anomaly detector* | "Policy and anomaly judge independently; a 'normal' anomaly result never rescues a failed policy check." |
| 11 | Security Event Logs | Filter Decision = DENY, open one event, export CSV | "Every decision is auditable and survives restarts." Stop and restart the app to prove persistence. |
| 12 | Users, Devices & Resources | Set `D-S01L` compliance to `noncompliant`; rerun step 3 | "Entity changes also affect decisions." Set it back to `compliant`. |

Suggested closing: limitations (synthetic data, author-chosen weights, single-user demo) and future scope.
