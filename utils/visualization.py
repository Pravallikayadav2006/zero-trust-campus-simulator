"""Plotly / NetworkX figure builders. Pure functions: data in, figure out (no Streamlit here)."""
from __future__ import annotations

import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objects as go

import config

COLORS = {
    config.DECISION_ALLOW: "#34d399",
    config.DECISION_FLAG: "#fbbf24",
    config.DECISION_DENY: "#f87171",
}
ACCENT = "#22d3ee"
TEXT = "#e6edf7"
MUTED = "#8a99b3"
GRID = "rgba(138,153,179,0.18)"
DECISION_ORDER = (config.DECISION_ALLOW, config.DECISION_FLAG, config.DECISION_DENY)


def _style(fig: go.Figure, title: str = "", height: int = 340) -> go.Figure:
    fig.update_layout(
        title=dict(text=title, font=dict(size=15, color=TEXT)),
        height=height,
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT, size=12),
        margin=dict(l=10, r=10, t=45, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID)
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def _empty(title: str, message: str = "No data yet") -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font=dict(size=14, color=MUTED))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, title)


# ------------------------------------------------------------------ dashboard charts
def activity_timeline(df: pd.DataFrame) -> go.Figure:
    title = "Access activity over time"
    if df is None or df.empty:
        return _empty(title)
    ts = pd.to_datetime(df["timestamp"])
    span = ts.max() - ts.min()
    freq = "h" if span <= pd.Timedelta(days=1) else ("6h" if span <= pd.Timedelta(days=10) else "D")
    counts = (df.assign(bucket=ts.dt.floor(freq)).groupby(["bucket", "decision"]).size()
              .unstack(fill_value=0))
    fig = go.Figure()
    for decision in DECISION_ORDER:
        y = counts[decision] if decision in counts.columns else [0] * len(counts)
        fig.add_bar(x=counts.index, y=y, name=decision.title(), marker_color=COLORS[decision])
    fig.update_layout(barmode="stack", bargap=0.15)
    fig.update_yaxes(title="Requests")
    return _style(fig, title)


def decision_breakdown(df: pd.DataFrame) -> go.Figure:
    title = "Decision breakdown"
    if df is None or df.empty:
        return _empty(title)
    counts = df["decision"].value_counts()
    labels = [d for d in DECISION_ORDER if d in counts.index]
    fig = go.Figure(go.Pie(
        labels=[d.title() for d in labels], values=[int(counts[d]) for d in labels], hole=0.55,
        marker=dict(colors=[COLORS[d] for d in labels]), textinfo="label+value+percent", sort=False,
    ))
    fig.update_layout(showlegend=False)
    return _style(fig, title)


def risk_distribution(df: pd.DataFrame) -> go.Figure:
    title = "Risk score distribution"
    if df is None or df.dropna(subset=["risk_score"]).empty:
        return _empty(title)
    data = df.dropna(subset=["risk_score"])
    fig = go.Figure()
    for decision in DECISION_ORDER:
        sub = data[data["decision"] == decision]
        if len(sub):
            fig.add_histogram(x=sub["risk_score"], name=decision.title(), marker_color=COLORS[decision],
                              xbins=dict(start=0, end=100, size=10))
    fig.update_layout(barmode="stack", bargap=0.08)
    fig.update_xaxes(title="Risk score (0-100)", range=[0, 100])
    fig.update_yaxes(title="Events")
    return _style(fig, title)


# ------------------------------------------------------------------ campus topology
# node id -> (label, kind, (x, y))
NODES = {
    "student_devices": ("Student devices", "device", (0.0, 2.0)),
    "faculty_devices": ("Faculty devices", "device", (0.0, 0.0)),
    "admin_devices": ("Admin devices", "device", (0.0, -2.0)),
    "gateway": ("Network gateway", "gateway", (2.2, 0.0)),
    "pep": ("Policy Enforcement Point", "pep", (4.4, 0.0)),
    "lms": ("Learning Mgmt System", "resource", (6.8, 3.2)),
    "library": ("Library systems", "resource", (6.8, 1.6)),
    "labs": ("Computer laboratories", "resource", (6.8, 0.0)),
    "app_server": ("Internal app server", "resource", (6.8, -1.6)),
    "admin_server": ("Administrative server", "resource", (6.8, -3.2)),
}
KIND_COLOR = {"device": "#60a5fa", "gateway": "#94a3b8", "pep": ACCENT, "resource": "#a78bfa"}


def campus_graph() -> nx.Graph:
    """Topology: every device reaches every resource ONLY through gateway -> PEP (no trust by location)."""
    g = nx.Graph()
    for node, (label, kind, pos) in NODES.items():
        g.add_node(node, label=label, kind=kind, pos=pos)
    for dev in config.ROLE_TO_DEVICE_NODE.values():
        g.add_edge(dev, "gateway")
    g.add_edge("gateway", "pep")
    for res in config.CATEGORY_TO_NODE.values():
        g.add_edge("pep", res)
    return g


def _line(x0, y0, x1, y1, color, width, dash=None, name=None):
    return go.Scatter(x=[x0, x1], y=[y0, y1], mode="lines", hoverinfo="skip", showlegend=False, name=name,
                      line=dict(color=color, width=width, dash=dash))


def topology_figure(path: dict | None = None, decision: str | None = None) -> go.Figure:
    """Draw the campus network; highlight the request path in the decision colour."""
    g = campus_graph()
    pos = {n: d["pos"] for n, d in g.nodes(data=True)}
    on_path: list[str] = list(path["nodes"]) if path else []
    path_edges = {frozenset(pair) for pair in zip(on_path, on_path[1:])}
    color = COLORS.get(decision, ACCENT)
    fig = go.Figure()
    for a, b in g.edges():
        if frozenset((a, b)) not in path_edges:
            fig.add_trace(_line(*pos[a], *pos[b], "rgba(138,153,179,0.35)", 1.5))
    for a, b in g.edges():
        if frozenset((a, b)) in path_edges:
            fig.add_trace(_line(*pos[a], *pos[b], color, 5))
    if path and path.get("target") and not path.get("reached_target"):
        fig.add_trace(_line(*pos["pep"], *pos[path["target"]], color, 2, dash="dot"))
    xs, ys, texts, hovers, colors, sizes, lines = [], [], [], [], [], [], []
    for node, data in g.nodes(data=True):
        xs.append(pos[node][0]); ys.append(pos[node][1]); texts.append(data["label"])
        hovers.append(f"{data['label']} ({data['kind']})")
        colors.append(KIND_COLOR[data["kind"]])
        active = node in on_path
        sizes.append(30 if active else 22)
        lines.append(dict(color=color if active else "rgba(0,0,0,0)", width=4))
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="markers+text", text=texts, textposition="bottom center", hovertext=hovers,
        hoverinfo="text", showlegend=False, textfont=dict(color=TEXT, size=11),
        marker=dict(size=sizes, color=colors, line=dict(width=[l["width"] for l in lines],
                                                        color=[l["color"] for l in lines])),
    ))
    if path and path.get("target") and not path.get("reached_target"):
        tx, ty = pos[path["target"]]
        fig.add_trace(go.Scatter(x=[tx], y=[ty], mode="markers", hoverinfo="skip", showlegend=False,
                                 marker=dict(size=34, symbol="x-thin-open", color=color, line=dict(width=3))))
    fig.update_xaxes(visible=False, range=[-1.2, 8.2])
    fig.update_yaxes(visible=False, range=[-4.2, 3.9])
    fig.update_layout(hovermode="closest")
    return _style(fig, "Simulated campus network (all traffic passes the policy enforcement point)", 430)


# ------------------------------------------------------------------ anomaly detection
def confusion_matrix_figure(cm: list[list[int]], title: str = "Confusion matrix") -> go.Figure:
    z = np.array(cm)
    labels = ["Normal", "Anomaly"]
    fig = go.Figure(go.Heatmap(
        z=z, x=[f"Predicted {l}" for l in labels], y=[f"Actual {l}" for l in labels], text=z.astype(str),
        texttemplate="%{text}", textfont=dict(size=18), colorscale=[[0, "#111a2e"], [1, ACCENT]],
        showscale=False, hoverinfo="skip",
    ))
    fig.update_yaxes(autorange="reversed")
    return _style(fig, title, 300)


def score_distribution(scores: np.ndarray, labels: np.ndarray) -> go.Figure:
    fig = go.Figure()
    for value, name, col in ((0, "Simulated normal", "#60a5fa"), (1, "Simulated anomaly", COLORS["FLAG"])):
        sel = np.asarray(labels) == value
        if sel.any():
            fig.add_histogram(x=np.asarray(scores)[sel], name=name, marker_color=col, opacity=0.75,
                              xbins=dict(start=0, end=100, size=5))
    fig.add_vline(x=50, line_dash="dash", line_color=MUTED, annotation_text="model decision boundary")
    fig.update_layout(barmode="overlay")
    fig.update_xaxes(title="Normalised anomaly indicator (0-100)", range=[0, 100])
    fig.update_yaxes(title="Test samples")
    return _style(fig, "Anomaly indicator on the labelled synthetic test set")


def per_type_recall(per_type: dict) -> go.Figure:
    if not per_type:
        return _empty("Recall per simulated anomaly type")
    kinds = sorted(per_type)
    fig = go.Figure(go.Bar(x=[k.replace("_", " ") for k in kinds], y=[per_type[k] for k in kinds],
                           marker_color=ACCENT, text=[f"{per_type[k]:.0%}" for k in kinds], textposition="outside"))
    fig.update_yaxes(range=[0, 1.15], tickformat=".0%")
    return _style(fig, "Recall per simulated anomaly type", 300)


def metrics_comparison(model: dict | None, rules: dict | None) -> go.Figure:
    fig = go.Figure()
    for name, m, col in (("Isolation Forest", model, ACCENT), ("Transparent rules", rules, "#a78bfa")):
        if m:
            fig.add_bar(x=["Precision", "Recall", "F1-score"], y=[m["precision"], m["recall"], m["f1"]], name=name,
                        marker_color=col, text=[f"{m[k]:.2f}" for k in ("precision", "recall", "f1")],
                        textposition="outside")
    fig.update_layout(barmode="group")
    fig.update_yaxes(range=[0, 1.15])
    return _style(fig, "Metrics on the synthetic test set", 300)
