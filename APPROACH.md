# Approach

## Prompting strategy

The baseline asks the model for DuckDB SQL and an explanation without showing the dataset schema. The improved prompt includes the exact schema, five sample rows, three few-shot examples, strict JSON instructions, and one repair attempt after a DuckDB error. Expected outcomes remain isolated from query generation and are used only for post-execution evaluation.

## Evaluation

Executability records first-try success and eventual success after one repair. Event-level outputs use precision, recall, and F1 over source row IDs or event IDs, with F1 >= 0.95 treated as a pass. Aggregated outputs require exact equality over the expected columns and counts. If a query returns raw events for an aggregated expected outcome, the evaluator first groups those events by the expected dimensions. The combined score weights accuracy at 70% and execution at 30%.

## Iteration

`main.py` runs the baseline and improved configurations over the same hypotheses and stores both outputs. Failures can be categorized from execution errors and metric results as schema hallucinations, invalid SQL, incorrect filters, or incorrect aggregation.

## Limitations and future work

The evaluation set is small and tied to one flattened CloudTrail schema. Grouped exact match is deliberately strict. LLM confidence is not calibrated. Future work could add a larger held-out hypothesis set, semantic SQL comparison, and calibrated confidence based on historical evaluation results.
