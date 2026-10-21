"""Anomaly detection: Isolation Forest with a transparent rule-based fallback.

Design notes
- The Isolation Forest is trained WITHOUT labels on a synthetic training set.
- It is evaluated on a separate synthetic test set (different seed) with known labels.
- Isolation Forest does not give reliable per-feature explanations, so the
  "why" shown to users comes from separate, readable threshold rules.
- The model is retrained deterministically at start-up (fixed seeds) instead of
  being loaded from a pickle file, which avoids unsafe deserialisation.
- If training fails for any reason the detector falls back to the rules and
  records a warning. The application keeps working.
"""
from __future__ import annotations

import logging
import math
from dataclasses import asdict, dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import config
from data.synthetic import FEATURES, generate_behavior_dataset, frequency_deviation

logger = logging.getLogger(__name__)

METHOD_IF = "isolation_forest"
METHOD_RULES = "rule_based_fallback"

BINARY_FEATURES = ("unusual_time", "device_compliant")
SIGNED_FEATURES = ("request_frequency_deviation",)
RULE_ANOMALY_THRESHOLD = 40
MIN_TRAIN_ROWS = 50


# --------------------------------------------------------------------- rules
def rule_assessment(features: dict) -> tuple[int, list[dict]]:
    """Transparent threshold rules. Returns (score 0-100, triggered rules)."""
    f = features
    triggered: list[dict] = []

    def hit(feature, points, text):
        triggered.append({"feature": feature, "value": f[feature], "points": points, "rule": text})

    if f["requests_per_window"] >= 20:
        hit("requests_per_window", 40, "20 or more requests in one 10-minute window (burst of requests)")
    if f["failed_auth_count"] >= 4:
        hit("failed_auth_count", 40, "4 or more failed authentication attempts")
    if f["distinct_resources"] >= 6:
        hit("distinct_resources", 40, "6 or more different resources requested (unexpected resource set)")
    if f["unusual_time"] == 1 and f["requests_per_window"] >= 8:
        hit("unusual_time", 40, "elevated activity outside normal hours")
    if f["device_compliant"] == 0 and f["failed_auth_count"] >= 2:
        hit("device_compliant", 40, "noncompliant device combined with repeated failed authentication")
    if f["failed_request_ratio"] >= 0.35:
        hit("failed_request_ratio", 25, "35% or more of requests failed")
    if f["request_frequency_deviation"] >= 5:
        hit("request_frequency_deviation", 25, "request rate far above this user's expected rate")
    score = min(100, sum(t["points"] for t in triggered))
    return score, triggered


def features_from_context(context: dict, device_compliant: bool) -> dict:
    """Turn a normalised request context into the model's feature vector."""
    lo, hi = config.UNUSUAL_HOURS
    hour = context["hour"]
    return {
        "requests_per_window": context["requests_per_window"],
        "failed_auth_count": context["failed_auth_count"],
        "access_frequency": context["access_frequency"],
        "unusual_time": 1 if (hour < lo or hour >= hi) else 0,
        "distinct_resources": context["distinct_resources"],
        "device_compliant": 1 if device_compliant else 0,
        "failed_request_ratio": context["failed_request_ratio"],
        "request_frequency_deviation": frequency_deviation(
            context["requests_per_window"], context["access_frequency"]
        ),
    }


# ------------------------------------------------------------------- results
@dataclass
class AnomalyResult:
    score: float                    # 0-100 normalised indicator (50 = model decision boundary)
    is_anomaly: bool
    method: str
    rule_score: int
    rule_flag: bool
    reasons: list = field(default_factory=list)
    raw_model_score: float | None = None
    imputed: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def detected(self) -> bool:
        """Combined verdict: the Isolation Forest OR the transparent rules fired.

        The two are complementary (the forest generalises, the rules are explainable), so the
        pipeline uses the union. It can only ever ADD scrutiny; it never grants access.
        """
        return bool(self.is_anomaly or self.rule_flag)

    @property
    def label(self) -> str:
        return "Anomaly detected" if self.detected else "No anomaly detected"


def check_no_leakage(train: pd.DataFrame, test: pd.DataFrame) -> None:
    """Raise if any feature row appears in both the training and the test set."""
    a = train[FEATURES].round(6)
    b = test[FEATURES].round(6)
    overlap = a.merge(b, how="inner", on=FEATURES)
    if len(overlap) > 0:
        raise ValueError(f"Train/test leakage: {len(overlap)} identical feature rows found.")


def prepare_frame(df: pd.DataFrame, medians: dict | None = None) -> tuple[pd.DataFrame, dict]:
    """Coerce to numeric, replace inf, and impute missing values with medians."""
    if df is None or len(df) == 0:
        raise ValueError("The dataset is empty.")
    missing_cols = [c for c in FEATURES if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing feature column(s): {', '.join(missing_cols)}.")
    x = df[FEATURES].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    if medians is None:
        medians = {}
        for c in FEATURES:
            med = x[c].median()
            if pd.isna(med):
                raise ValueError(f"Feature '{c}' has no valid values.")
            medians[c] = float(med)
    x = x.fillna(value=medians)
    return x.astype(float), medians


def validate_features(features: dict, medians: dict | None) -> tuple[dict, list]:
    """Validate one feature dict. Missing values are imputed; wrong types/ranges raise ValueError."""
    if not isinstance(features, dict):
        raise ValueError("Features must be a dictionary.")
    clean: dict = {}
    imputed: list = []
    for name in FEATURES:
        raw = features.get(name)
        if raw is None or (isinstance(raw, float) and math.isnan(raw)):
            if medians is None or name not in medians:
                raise ValueError(f"Feature '{name}' is missing and no default is available.")
            clean[name] = medians[name]
            imputed.append(name)
            continue
        if isinstance(raw, bool) or not isinstance(raw, (int, float, np.integer, np.floating)):
            raise ValueError(f"Feature '{name}' must be numeric.")
        value = float(raw)
        if math.isinf(value):
            raise ValueError(f"Feature '{name}' must be finite.")
        if name in BINARY_FEATURES and value not in (0.0, 1.0):
            raise ValueError(f"Feature '{name}' must be 0 or 1.")
        if name not in SIGNED_FEATURES and value < 0:
            raise ValueError(f"Feature '{name}' must not be negative.")
        if name == "failed_request_ratio" and value > 1:
            raise ValueError("Feature 'failed_request_ratio' must be between 0 and 1.")
        clean[name] = value
    return clean, imputed


# ------------------------------------------------------------------ detector
class AnomalyDetector:
    def __init__(
        self,
        seed: int = config.RANDOM_SEED,
        n_train: int = 1500,
        n_test: int = 600,
        train_anomaly_fraction: float = 0.05,
        test_anomaly_fraction: float = 0.12,
        n_estimators: int = 200,
    ):
        self.seed = seed
        self.n_train = n_train
        self.n_test = n_test
        self.train_anomaly_fraction = train_anomaly_fraction
        self.test_anomaly_fraction = test_anomaly_fraction
        self.n_estimators = n_estimators
        self.pipeline: Pipeline | None = None
        self.medians: dict | None = None
        self.method = METHOD_RULES
        self.warning: str | None = "Model has not been trained yet; using rule-based fallback."
        self.train_df: pd.DataFrame | None = None
        self.test_df: pd.DataFrame | None = None
        self.metrics: dict | None = None
        self.rule_metrics: dict | None = None

    # ---------------------------------------------------------------- training
    def fit(self) -> "AnomalyDetector":
        """Generate data, train and evaluate. Never raises; falls back to rules on failure."""
        try:
            self.train_df = generate_behavior_dataset(self.n_train, self.train_anomaly_fraction, self.seed)
            self.test_df = generate_behavior_dataset(self.n_test, self.test_anomaly_fraction, self.seed + 1000)
            check_no_leakage(self.train_df, self.test_df)
            self.fit_from_dataframe(self.train_df)
            self.metrics = self.evaluate(self.test_df)
            self.warning = None
        except Exception as exc:  # noqa: BLE001 - logged and reported, then fallback is used
            logger.exception("Anomaly model training failed; using rule-based fallback.")
            self.pipeline = None
            self.method = METHOD_RULES
            self.metrics = None
            self.warning = f"Isolation Forest training failed ({type(exc).__name__}: {exc}). Using the rule-based fallback."
        if self.test_df is not None:
            try:
                self.rule_metrics = self.evaluate(self.test_df, use_rules=True)
            except Exception:  # noqa: BLE001
                logger.exception("Could not evaluate the rule-based detector.")
                self.rule_metrics = None
        return self

    def fit_from_dataframe(self, train_df: pd.DataFrame) -> None:
        if train_df is None or len(train_df) == 0:
            raise ValueError("Training data is empty.")
        if len(train_df) < MIN_TRAIN_ROWS:
            raise ValueError(f"Need at least {MIN_TRAIN_ROWS} training rows, got {len(train_df)}.")
        x, medians = prepare_frame(train_df)
        pipe = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "forest",
                    IsolationForest(
                        n_estimators=self.n_estimators,
                        contamination=self.train_anomaly_fraction,
                        random_state=self.seed,
                    ),
                ),
            ]
        )
        pipe.fit(x)  # labels are never used for training
        self.pipeline = pipe
        self.medians = medians
        self.method = METHOD_IF

    # -------------------------------------------------------------- evaluation
    def evaluate(self, test_df: pd.DataFrame, use_rules: bool = False) -> dict:
        if test_df is None or len(test_df) == 0:
            raise ValueError("The test dataset is empty.")
        if "label" not in test_df.columns:
            raise ValueError("The test dataset needs a 'label' column.")
        if use_rules:
            x, _ = prepare_frame(test_df, self.medians or {c: 0.0 for c in FEATURES})
            preds = np.array(
                [int(rule_assessment(row.to_dict())[0] >= RULE_ANOMALY_THRESHOLD) for _, row in x.iterrows()]
            )
        else:
            if self.pipeline is None:
                raise ValueError("The Isolation Forest has not been trained.")
            x, _ = prepare_frame(test_df, self.medians)
            preds = (self.pipeline.predict(x) == -1).astype(int)
        y = test_df["label"].astype(int).to_numpy()
        precision, recall, f1, _ = precision_recall_fscore_support(
            y, preds, average="binary", pos_label=1, zero_division=0
        )
        tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
        per_type = {}
        if "anomaly_type" in test_df.columns:
            for kind in test_df.loc[test_df["label"] == 1, "anomaly_type"].unique():
                mask = (test_df["anomaly_type"] == kind).to_numpy()
                per_type[str(kind)] = float(preds[mask].mean())
        return {
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "n_samples": int(len(y)),
            "n_anomalies": int(y.sum()),
            "per_type_recall": per_type,
        }

    # --------------------------------------------------------------- inference
    @staticmethod
    def _normalise(raw_decision: float) -> float:
        # decision_function < 0 means "anomaly"; flip the sign so 50 sits on the boundary.
        return float(100.0 / (1.0 + math.exp(-15.0 * (-raw_decision))))

    def analyze(self, features: dict) -> AnomalyResult:
        clean, imputed = validate_features(features, self.medians)
        rule_score, reasons = rule_assessment(clean)
        rule_flag = rule_score >= RULE_ANOMALY_THRESHOLD
        if self.pipeline is not None and self.method == METHOD_IF:
            frame = pd.DataFrame([clean], columns=FEATURES)
            raw = float(self.pipeline.decision_function(frame)[0])
            is_anomaly = bool(self.pipeline.predict(frame)[0] == -1)
            return AnomalyResult(
                score=round(self._normalise(raw), 1),
                is_anomaly=is_anomaly,
                method=METHOD_IF,
                rule_score=rule_score,
                rule_flag=rule_flag,
                reasons=reasons,
                raw_model_score=raw,
                imputed=imputed,
            )
        return AnomalyResult(
            score=float(rule_score),
            is_anomaly=rule_flag,
            method=METHOD_RULES,
            rule_score=rule_score,
            rule_flag=rule_flag,
            reasons=reasons,
            raw_model_score=None,
            imputed=imputed,
        )

    def score_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        """Normalised 0-100 anomaly indicator for every row (Isolation Forest only)."""
        if self.pipeline is None:
            raise ValueError("The Isolation Forest has not been trained.")
        x, _ = prepare_frame(df, self.medians)
        return np.array([self._normalise(v) for v in self.pipeline.decision_function(x)])

    def status(self) -> dict:
        return {
            "method": self.method,
            "warning": self.warning,
            "seed": self.seed,
            "train_rows": None if self.train_df is None else int(len(self.train_df)),
            "test_rows": None if self.test_df is None else int(len(self.test_df)),
            "n_estimators": self.n_estimators,
            "metrics": self.metrics,
            "rule_metrics": self.rule_metrics,
        }
