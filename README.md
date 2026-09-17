# AI Threat Hunting Query Generation

This project converts natural-language AWS CloudTrail hunting hypotheses into executable DuckDB SQL, explains each query, and evaluates its results against held-out expected outcomes.

## Architecture

```mermaid
flowchart TD
    H[hypotheses.json] --> G[QueryGenerator]
    S[CSV schema and samples] --> G
    G --> Q[SQL and explanation]
    Q --> D[DuckDB executor]
    C[CloudTrail CSV] --> D
    D --> E[Evaluator]
    O[hypotheses_outcomes.json] --> E
    E --> R[evaluation_results.json]
    E --> M[EVALUATION_REPORT.md]
```

Expected outcomes are isolated from query generation and are loaded only for offline scoring.

## Setup and run

```bash
uv sync
```

Put `nineteenFeaturesDf.csv` at `data/nineteenFeaturesDf.csv` from Kaggle (https://www.kaggle.com/datasets/nobukim/aws-cloudtrails-dataset-from-flaws-cloud?resource=download&select=nineteenFeaturesDf.csv), then create `.env`:

```text
GROQ_API_KEY=your_key_here
GROQ_MODEL=openai/gpt-oss-20b
```

Inspect the detected schema without an API call:

```bash
uv run python main.py --inspect
```

Run baseline and improved evaluations:

```bash
uv run python main.py
uv run pytest -q
```

The run writes `evaluation_results.json` and `EVALUATION_REPORT.md`.

## Design decisions

DuckDB queries the 1 GB CSV without loading it fully into application memory. SQL is executable, inspectable, and supports filtering and aggregation directly. One retry repairs execution errors; successful but inaccurate queries are retained for honest failure analysis.

## Extending to another dataset

Change the CSV path and table name in `main.py`. Schema and samples are discovered at runtime. Update the few-shot examples so they match the new dataset's domain and columns.
