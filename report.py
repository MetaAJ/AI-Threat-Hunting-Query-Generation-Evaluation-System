from pathlib import Path
from typing import Any


def write_report(results: dict[str, Any], path: Path = Path("EVALUATION_REPORT.md")) -> None:
    baseline = results["baseline"]["summary"]
    improved = results["improved"]["summary"]
    lines = [
        "# Evaluation Report",
        "",
        "## Before and after",
        "",
        "| Metric | Baseline | Improved |",
        "|---|---:|---:|",
    ]
    for key in baseline:
        if key != "queries":
            label = key.replace("_", " ").title()
            lines.append(f"| {label} | {baseline[key]:.4f} | {improved[key]:.4f} |")

    lines.extend([
        "",
        "Executability measures valid DuckDB execution; a repaired query receives partial "
        "execution credit. Event results use precision, recall, and F1 over event identifiers, "
        "with F1 >= 0.95 treated as a pass. "
        "Grouped/count results require an exact match. The overall score weights accuracy at "
        "70% and execution at 30%.",
        "",
        "## Improved run by hypothesis",
        "",
        "| ID | Hypothesis | Executed | Retried | Accuracy | Weighted score |",
        "|---|---|---:|---:|---:|---:|",
    ])
    for item in results["improved"]["items"]:
        hypothesis = item["hypothesis"].replace("|", "\\|")
        lines.append(
            f"| {item['id']} | {hypothesis} | {item['executed']} | {item['retried']} | "
            f"{item['metrics']['accuracy_score']:.4f} | {item['weighted_score']:.4f} |"
        )

    categories: dict[str, int] = {}
    for item in results["improved"]["items"]:
        category = item["failure_category"]
        if category:
            categories[category] = categories.get(category, 0) + 1

    lines.extend([
        "",
        "## Failure analysis",
        "",
        (
            "Observed failure categories: "
            + (", ".join(f"{key}: {value}" for key, value in sorted(categories.items())) or "none")
            + "."
        ),
        "The improved prompt addresses schema and syntax failures with exact schema grounding, "
        "examples, and one execution-error repair attempt. Result mismatches remain visible rather "
        "than being silently corrected with evaluation labels.",
        "",
        "## Generated queries and explanations",
        "",
    ])
    for item in results["improved"]["items"]:
        lines.extend([
            f"### {item['id']}: {item['name']}",
            "",
            f"**Interpretation:** {item['interpretation'] or 'Generation failed.'}",
            "",
            f"**Confidence:** {item['confidence']:.2f}",
            "",
            f"**Reasoning:** {item['reasoning'] or 'Unavailable.'}",
            "",
            "```sql",
            item["sql"] or "-- No SQL generated",
            "```",
            "",
            f"**Result:** executed={item['executed']}, passed={item['metrics']['passed']}, "
            f"accuracy={item['metrics']['accuracy_score']:.4f}",
            "",
        ])

    lines.extend([
        "",
        "## Limitations",
        "",
        "The evaluation set is small and comes from one CloudTrail dataset. Exact grouped-result "
        "matching is strict. LLM confidence is a self-assessment, not a calibrated probability.",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")
