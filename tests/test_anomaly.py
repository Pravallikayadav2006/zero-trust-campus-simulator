"""Anomaly detection tests: reproducibility, leakage, validation and fallback."""
import numpy as np
import pandas as pd
import pytest

from data.synthetic import FEATURES, generate_behavior_dataset
from models.anomaly import (METHOD_IF, METHOD_RULES, AnomalyDetector, check_no_leakage, prepare_frame,
                            rule_assessment)

NORMAL = {"requests_per_window": 3, "failed_auth_count": 0, "access_frequency": 18.0, "unusual_time": 0,
          "distinct_resources": 1, "device_compliant": 1, "failed_request_ratio": 0.0,
          "request_frequency_deviation": 0.0}
BURST = dict(NORMAL, requests_per_window=60, request_frequency_deviation=19.0)


def test_dataset_is_reproducible_and_labelled():
    a = generate_behavior_dataset(300, 0.1, seed=7)
    b = generate_behavior_dataset(300, 0.1, seed=7)
    pd.testing.assert_frame_equal(a, b)
    assert a["label"].sum() == 30 and (a["is_simulated"] == 1).all()
    assert set(FEATURES) <= set(a.columns)


def test_different_seeds_differ():
    assert not generate_behavior_dataset(200, 0.1, 1).equals(generate_behavior_dataset(200, 0.1, 2))


def test_training_is_reproducible():
    a, b = AnomalyDetector(n_train=400, n_test=200).fit(), AnomalyDetector(n_train=400, n_test=200).fit()
    assert a.analyze(BURST).score == b.analyze(BURST).score
    assert a.metrics == b.metrics


def test_trained_model_used_and_separates_obvious_cases(detector):
    assert detector.method == METHOD_IF and detector.warning is None
    normal, burst = detector.analyze(NORMAL), detector.analyze(BURST)
    assert not normal.detected and burst.detected
    assert burst.score > normal.score


def test_train_and_test_sets_are_disjoint(detector):
    check_no_leakage(detector.train_df, detector.test_df)          # raises on overlap
    with pytest.raises(ValueError, match="leakage"):
        check_no_leakage(detector.train_df, detector.train_df.head(5))


def test_metrics_are_computed_on_labelled_test_set(detector):
    m = detector.metrics
    (tn, fp), (fn, tp) = m["confusion_matrix"]
    assert tn + fp + fn + tp == m["n_samples"] == len(detector.test_df)
    assert tp + fn == m["n_anomalies"]
    for k in ("precision", "recall", "f1"):
        assert 0.0 <= m[k] <= 1.0


def test_empty_dataset_rejected():
    with pytest.raises(ValueError, match="empty"):
        prepare_frame(pd.DataFrame(columns=FEATURES))
    with pytest.raises(ValueError, match="empty"):
        AnomalyDetector().fit_from_dataframe(pd.DataFrame())


def test_too_small_training_set_rejected():
    with pytest.raises(ValueError, match="at least"):
        AnomalyDetector().fit_from_dataframe(generate_behavior_dataset(10, 0.1, 1))


def test_missing_values_are_imputed(detector):
    row = dict(NORMAL)
    row["access_frequency"] = None
    result = detector.analyze(row)
    assert "access_frequency" in result.imputed


@pytest.mark.parametrize("bad", [
    {"requests_per_window": -1}, {"requests_per_window": "many"}, {"failed_request_ratio": 1.5},
    {"unusual_time": 2}, {"failed_auth_count": float("inf")}, {"device_compliant": True},
])
def test_invalid_inputs_rejected(detector, bad):
    with pytest.raises(ValueError):
        detector.analyze(dict(NORMAL, **bad))


def test_non_dict_input_rejected(detector):
    with pytest.raises(ValueError):
        detector.analyze([1, 2, 3])


def test_dataframe_with_nan_and_inf_is_cleaned():
    df = generate_behavior_dataset(100, 0.1, 3).astype({"requests_per_window": float, "failed_auth_count": float})
    df.loc[0, "requests_per_window"] = np.nan
    df.loc[1, "failed_auth_count"] = np.inf
    x, medians = prepare_frame(df)
    assert not x.isna().any().any() and np.isfinite(x.to_numpy()).all() and set(medians) == set(FEATURES)


def test_fallback_when_training_fails():
    class Broken(AnomalyDetector):
        def fit_from_dataframe(self, train_df):
            raise RuntimeError("boom")

    d = Broken().fit()                              # must not raise
    assert d.method == METHOD_RULES and "boom" in d.warning and d.metrics is None
    assert d.analyze(BURST).detected and not d.analyze(NORMAL).detected
    assert d.analyze(BURST).method == METHOD_RULES


def test_rules_explain_themselves():
    score, reasons = rule_assessment(dict(NORMAL, failed_auth_count=6, failed_request_ratio=0.6))
    assert score >= 40
    assert {r["feature"] for r in reasons} == {"failed_auth_count", "failed_request_ratio"}
    assert rule_assessment(NORMAL) == (0, [])
