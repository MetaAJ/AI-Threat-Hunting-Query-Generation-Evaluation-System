from typing import Any

import pandas as pd


def _event_identifiers(
    actual: pd.DataFrame, expected: pd.DataFrame
) -> tuple[set[Any], set[Any], str]:
    if "eventID" in actual.columns and "eventID" in expected.columns:
        return set(actual["eventID"].dropna()), set(expected["eventID"].dropna()), "eventID"
    if "_row_id" in actual.columns and "_row_id" in expected.columns:
        return (
            set(actual["_row_id"].astype(str)),
            set(expected["_row_id"].astype(str)),
            "_row_id",
        )
    common = sorted(set(actual.columns) & set(expected.columns))
    if not common:
        return set(), set(), "unavailable"
    return _normalized_rows(actual[common]), _normalized_rows(expected[common]), "row_values"


def _normalized_rows(frame: pd.DataFrame) -> set[tuple[Any, ...]]:
    normalized = frame.copy().fillna("<NULL>")
    for column in normalized.columns:
        normalized[column] = normalized[column].map(_normalize_value)
    return set(normalized.itertuples(index=False, name=None))


def _normalize_value(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return str(value).strip()


def evaluate_result(actual: pd.DataFrame, expected: pd.DataFrame) -> dict[str, Any]:
    if "count" in expected.columns:
        return evaluate_grouped_result(actual, expected)
    return evaluate_event_result(actual, expected)


def evaluate_event_result(actual: pd.DataFrame, expected: pd.DataFrame) -> dict[str, Any]:
    actual_ids, expected_ids, identifier = _event_identifiers(actual, expected)
    true_positives = len(actual_ids & expected_ids)
    precision = true_positives / len(actual_ids) if actual_ids else 0.0
    recall = true_positives / len(expected_ids) if expected_ids else float(not actual_ids)
    f1 = (2*precision*recall / (precision+recall)) if precision+recall else 0.0
    return {
        "metric_type": "event_rows",
        "identifier": identifier,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "actual_rows": len(actual),
        "expected_rows": len(expected),
        "exact_match": f1 == 1.0,
        "passed": f1 >= 0.95,
        "accuracy_score": round(f1, 4),
    }


def evaluate_grouped_result(actual: pd.DataFrame, expected: pd.DataFrame) -> dict[str, Any]:
    group_columns = [column for column in expected.columns if column != "count"]
    if "count" not in actual.columns and set(group_columns) <= set(actual.columns):
        actual = (
            actual.groupby(group_columns, dropna=False)
            .size()
            .reset_index(name="count")
        )

    missing_columns = set(expected.columns) - set(actual.columns)
    if missing_columns:
        return {
            "metric_type": "grouped_exact_match",
            "exact_match": 0.0,
            "actual_rows": len(actual),
            "expected_rows": len(expected),
            "missing_columns": sorted(missing_columns),
            "passed": False,
            "accuracy_score": 0.0,
        }

    actual_tuples = _normalized_rows(actual[list(expected.columns)])
    expected_tuples = _normalized_rows(expected)
    exact_match = float(actual_tuples == expected_tuples)

    true_positives = len(actual_tuples & expected_tuples)
    precision = true_positives / len(actual_tuples) if actual_tuples else 0.0
    recall = true_positives / len(expected_tuples) if expected_tuples else float(not actual_tuples)
    overlap_f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "metric_type": "grouped_exact_match",
        "exact_match": exact_match,
        "actual_rows": len(actual),
        "expected_rows": len(expected),
        "missing_columns": [],
        "passed": bool(exact_match),
        "accuracy_score": round(overlap_f1, 4),
        "overlap_precision": round(precision, 4),
        "overlap_recall": round(recall, 4),
    }


def score_execution(executed: bool, retried: bool) -> float:
    if not executed:
        return 0.0
    return 0.8 if retried else 1.0


def weighted_score(execution_score: float, accuracy_score: float) -> float:
    return round(0.3*execution_score + 0.7*accuracy_score, 4)
