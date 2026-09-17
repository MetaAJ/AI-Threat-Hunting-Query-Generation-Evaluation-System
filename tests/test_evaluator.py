import pandas as pd

from evaluator import (
    evaluate_event_result,
    evaluate_grouped_result,
    score_execution,
    weighted_score,
)


def test_event_metrics_use_source_row_ids() -> None:
    actual = pd.DataFrame({"_row_id": [10, 20, 30]})
    expected = pd.DataFrame({"_row_id": ["10", "20"], "eventName": ["a", "b"]})
    result = evaluate_event_result(actual, expected)
    assert result["precision"] == 0.6667
    assert result["recall"] == 1.0
    assert result["f1"] == 0.8
    assert result["passed"] is False


def test_event_metrics_pass_for_exact_event_ids() -> None:
    actual = pd.DataFrame({"eventID": ["a", "b"]})
    expected = pd.DataFrame({"eventID": ["b", "a"]})

    result = evaluate_event_result(actual, expected)

    assert result["identifier"] == "eventID"
    assert result["f1"] == 1.0
    assert result["passed"] is True


def test_grouped_metrics_ignore_row_order() -> None:
    actual = pd.DataFrame({"eventName": ["b", "a"], "count": [2, 1]})
    expected = pd.DataFrame({"eventName": ["a", "b"], "count": [1, 2]})
    result = evaluate_grouped_result(actual, expected)
    assert result["exact_match"] == 1.0
    assert result["passed"] is True


def test_grouped_metrics_can_aggregate_event_rows() -> None:
    actual = pd.DataFrame({"eventName": ["a", "a", "b"], "other": [1, 2, 3]})
    expected = pd.DataFrame({"eventName": ["a", "b"], "count": [2, 1]})

    result = evaluate_grouped_result(actual, expected)

    assert result["exact_match"] == 1.0


def test_grouped_metrics_fail_for_wrong_counts() -> None:
    actual = pd.DataFrame({"eventName": ["a", "b"], "count": [3, 1]})
    expected = pd.DataFrame({"eventName": ["a", "b"], "count": [2, 1]})

    result = evaluate_grouped_result(actual, expected)

    assert result["exact_match"] == 0.0
    assert result["passed"] is False


def test_execution_scoring() -> None:
    assert score_execution(executed=False, retried=False) == 0.0
    assert score_execution(executed=True, retried=False) == 1.0
    assert score_execution(executed=True, retried=True) == 0.8


def test_weighted_score_prioritizes_accuracy() -> None:
    assert weighted_score(execution_score=1.0, accuracy_score=1.0) == 1.0
    assert weighted_score(execution_score=1.0, accuracy_score=0.0) == 0.3
    assert weighted_score(execution_score=0.0, accuracy_score=1.0) == 0.7
