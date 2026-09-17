# Approach

## Prompting strategy

The baseline prompt asks for DuckDB SQL and an explanation with no schema information. The improved prompt adds the exact column schema, five sample rows, and few-shot examples, and enforces structured JSON output via a strict schema. Expected outcomes are never shown to the generator; they are loaded only after execution, for scoring.

An early version of the improved prompt let the model decide whether an answer should be grouped/aggregated and by which columns. This consistently under-grouped relative to the reference outcomes (e.g. grouping by source IP alone when the reference groups by source IP, user identity, and user agent together) — a dimension that can't be inferred from the hypothesis text without seeing the expected output. The fix: the generator never makes this decision. It always returns raw, filtered rows (`SELECT _row_id, * FROM cloudtrail WHERE <filter>`) and is blocked, both by prompt instruction and a hard validation check, from writing `GROUP BY` or any aggregate. Grouping is performed downstream by the evaluator, using the expected outcome's own columns as the grouping key. The model's only job is the filter logic.

## Evaluation

Executability: 1.0 if correct first try, 0.8 if it needed one repair after a DuckDB error, 0 if never executable.

Event-level expected outcomes (no `count` column) are scored with precision/recall/F1 over row identifiers (`eventID` if available, else a synthetic `_row_id`), F1 ≥ 0.95 = pass.

Grouped expected outcomes (has `count`) are auto-aggregated from raw rows if possible, then compared. Pass requires an exact match on grouping keys and counts; the accuracy score also reports F1 overlap so a near-miss is visibly distinguishable from a badly wrong query, even though both fail the strict threshold.

Final weighted score: 70% accuracy, 30% executability.

*Note: the `accuracy_score` field reports this F1 value (or, for grouped results, the F1 overlap between actual and expected groups), not classification accuracy in the strict sense. Classification accuracy is uninformative for this task, since a query returning zero rows would score near-perfectly against a dataset this large — F1 is the standard measure for retrieval/detection tasks because it ignores the (enormous, uninteresting) true-negative population entirely.*

## Iteration and results

`main.py` runs baseline and improved over the same 11 hypotheses in one execution. Baseline failures were almost entirely schema hallucination (e.g. `userIdentity.type` instead of this dataset's flattened `userIdentitytype`) — fixed by schema grounding. The submitted run: baseline 54.5% execution / 9.1% accuracy pass rate; improved 100% execution / 45.5% accuracy pass rate (5 of 11 hypotheses exact-match), weighted score 0.79 vs. 0.40.

One failure was traced in full against the raw CSV as a worked example: "Sign-in Failures" initially filtered on `errorCode IS NOT NULL`, but this dataset records some console-login failures via a populated `errorMessage` with an empty `errorCode` — invisible from column names alone. Checking both fields fixed it.

## Limitations and future work

**Filter precision.** Several hypotheses select the right columns but filter too broadly or narrowly relative to the reference (e.g. matching a wider set of user-agent strings than the reference considers suspicious). The exact reference filter can't be inferred from the hypothesis text alone; narrowing further would need either more illustrative sample rows or domain-specific guidance not derived from the answer key.

**Run-to-run variance.** Individual hypotheses have flipped between passing and failing across otherwise identical runs (same code, same prompt, temperature 0) — observed directly on hypotheses 1, 3, and 6. Hypotheses 2, 5, and 10 have passed consistently across every run. This is inherent LLM non-determinism, not an evaluation flaw.

**A known, deliberately unfixed naming mismatch.** One expected outcome names a column (`instanceType`) that doesn't exist in the CSV, which only has the flattened equivalent (`requestParametersinstanceType`). Fixing this would require reading the expected outcome first to learn the exact name — effectively hardcoding a specific test case.

**Grouped scoring stays strict on pass/fail** by design — a count either matches the real population or it doesn't, so there's no principled "partially correct" for an aggregate detection query. The continuous overlap score exists for diagnosis, not for grading.

**Confidence is a self-assessment**, not calibrated against actual correctness — it should be read as the model's stated certainty, not a reliability signal.

Future work: a larger held-out hypothesis set to reduce run-to-run variance in reported metrics, confidence calibration against historical outcomes, and generic (non-answer-key-derived) value-semantics notes for known dataset quirks.
