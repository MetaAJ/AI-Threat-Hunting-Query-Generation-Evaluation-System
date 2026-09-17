import argparse
import json
import os
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd
from dotenv import load_dotenv

from evaluator import evaluate_result, score_execution, weighted_score
from query_generator import QueryGenerator
from report import write_report
from utils import load_hypotheses_outcomes


CSV_PATH = Path("data/nineteenFeaturesDf.csv")
HYPOTHESES_PATH = Path("hypotheses.json")
OUTCOMES_PATH = Path("hypotheses_outcomes.json")


def load_hypotheses(path: Path = HYPOTHESES_PATH) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def open_database(csv_path: Path = CSV_PATH) -> duckdb.DuckDBPyConnection:
    if not csv_path.exists():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")
    connection = duckdb.connect()
    safe_path = str(csv_path.resolve()).replace("'", "''")
    connection.execute(
        "CREATE VIEW cloudtrail AS "
        "SELECT row_number() OVER () - 1 AS _row_id, * "
        f"FROM read_csv_auto('{safe_path}', header=true, all_varchar=true)"
    )
    return connection


def describe_data(connection: duckdb.DuckDBPyConnection) -> str:
    columns = connection.execute("DESCRIBE cloudtrail").fetchdf()
    sample = connection.execute("SELECT * FROM cloudtrail LIMIT 5").fetchdf()
    return (
        "Columns and DuckDB types:\n"
        + columns[["column_name", "column_type"]].to_string(index=False)
        + "\n\nFive sample rows:\n"
        + sample.to_string(index=False)
    )


def execute_query(
    connection: duckdb.DuckDBPyConnection, sql: str
) -> tuple[pd.DataFrame | None, str | None]:
    try:
        return connection.execute(sql).fetchdf(), None
    except duckdb.Error as exc:
        return None, str(exc)


def run_one(
    connection: duckdb.DuckDBPyConnection,
    generator: QueryGenerator,
    hypothesis: dict[str, str],
    expected: pd.DataFrame,
    *,
    improved: bool,
) -> dict[str, Any]:
    try:
        generated = generator.generate(hypothesis["hypothesis"], improved=improved)
    except Exception as exc:
        return {
            "id": hypothesis["id"],
            "name": hypothesis["name"],
            "hypothesis": hypothesis["hypothesis"],
            "sql": None,
            "interpretation": None,
            "reasoning": None,
            "assumptions": [],
            "confidence": 0.0,
            "executed": False,
            "retried": False,
            "execution_error": None,
            "generation_error": str(exc),
            "failure_category": "generation_error",
            "metrics": {"metric_type": "not_executed", "passed": False, "accuracy_score": 0.0},
            "weighted_score": 0.0,
        }
    print(f"    Interpretation: {generated['interpretation']}")
    print(f"    SQL: {generated['sql']}")
    print(f"    Confidence: {float(generated['confidence']):.2f}")
    actual, error = execute_query(connection, generated["sql"])
    retried = False

    if error and improved:
        retried = True
        generated = generator.generate(
            hypothesis["hypothesis"],
            improved=True,
            previous=generated,
            execution_error=error,
        )
        actual, error = execute_query(connection, generated["sql"])

    executed = error is None and actual is not None
    metrics = (
        evaluate_result(actual, expected)
        if executed
        else {"metric_type": "not_executed", "passed": False, "accuracy_score": 0.0}
    )
    execution_score = score_execution(executed, retried)

    return {
        "id": hypothesis["id"],
        "name": hypothesis["name"],
        "hypothesis": hypothesis["hypothesis"],
        "sql": generated["sql"],
        "interpretation": generated["interpretation"],
        "reasoning": generated["reasoning"],
        "assumptions": generated["assumptions"],
        "confidence": float(generated["confidence"]),
        "executed": executed,
        "retried": retried,
        "execution_error": error,
        "generation_error": None,
        "failure_category": (
            None if metrics["passed"] else ("execution_error" if not executed else "result_mismatch")
        ),
        "metrics": metrics,
        "weighted_score": weighted_score(execution_score, metrics["accuracy_score"]),
    }


def summarize(run: list[dict[str, Any]]) -> dict[str, float | int]:
    count = len(run) or 1
    return {
        "queries": len(run),
        "first_try_execution_rate": round(
            sum(item["executed"] and not item["retried"] for item in run) / count, 4
        ),
        "eventual_execution_rate": round(sum(item["executed"] for item in run) / count, 4),
        "accuracy_pass_rate": round(sum(item["metrics"]["passed"] for item in run) / count, 4),
        "overall_weighted_score": round(sum(item["weighted_score"] for item in run) / count, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--inspect", 
        action="store_true", 
        help="Print schema/sample without calling the LLM"
    )
    parser.add_argument(
        "--generate-only",
        action="store_true",
        help="Print generated SQL and explanations without executing or scoring",
    )
    args = parser.parse_args()

    load_dotenv()
    connection = open_database()
    schema_description = describe_data(connection)
    print(schema_description)
    if args.inspect:
        return
    if not os.getenv("GROQ_API_KEY"):
        raise RuntimeError("Set GROQ_API_KEY in .env before running the evaluation")

    hypotheses = load_hypotheses()
    generator = QueryGenerator(schema_description)
    if args.generate_only:
        print("\nGenerating improved queries without execution or scoring...")
        for hypothesis in hypotheses:
            print(f"\n{hypothesis['id']}: {hypothesis['name']}")
            generated = generator.generate(hypothesis["hypothesis"], improved=True)
            print(f"Interpretation: {generated['interpretation']}")
            print(f"Reasoning: {generated['reasoning']}")
            print("Assumptions:")
            for assumption in generated["assumptions"]:
                print(f"  - {assumption}")
            print(f"Confidence: {float(generated['confidence']):.2f}")
            print(f"SQL: {generated['sql']}")
        return

    outcomes = load_hypotheses_outcomes(OUTCOMES_PATH)
    all_results: dict[str, Any] = {}

    for run_name, improved in (("baseline", False), ("improved", True)):
        items = []
        print(f"\nRunning {run_name} evaluation...")
        for hypothesis in hypotheses:
            print(f"  {hypothesis['id']}: {hypothesis['name']}")
            items.append(
                run_one(
                    connection,
                    generator,
                    hypothesis,
                    outcomes[hypothesis["id"]],
                    improved=improved,
                )
            )
        all_results[run_name] = {"summary": summarize(items), "items": items}

    Path("evaluation_results.json").write_text(
        json.dumps(all_results, indent=2), encoding="utf-8"
    )
    write_report(all_results)
    summary = pd.DataFrame(
        {name: values["summary"] for name, values in all_results.items()}
    )
    print("\nEvaluation summary:\n", summary.to_string())


if __name__ == "__main__":
    main()
