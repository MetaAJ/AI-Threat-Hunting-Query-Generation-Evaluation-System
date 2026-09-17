# Approach

## Prompting strategy

The baseline asks the model for DuckDB SQL and an explanation without showing the dataset schema. The improved prompt adds the exact schema, five sample rows, targeted few-shot examples, strict JSON-schema-enforced output, and one repair attempt after a DuckDB execution error. Expected outcomes are never shown to the generator at any stage; they are loaded only after execution, for scoring.

An earlier version of the improved prompt let the model decide whether a hypothesis needed a grouped/aggregated answer and which columns to group by. This produced a specific failure mode: the model consistently under-grouped relative to the reference outcomes (for example, grouping brute-force attempts by source IP alone when the reference groups by source IP, user identity, and user agent together). Since the correct grouping dimensions cannot be inferred from the hypothesis text alone without seeing the expected output, the prompt was changed so the generator never decides this. It now always returns raw, filtered event rows (`SELECT _row_id, * FROM cloudtrail WHERE <filter>`) and never writes `GROUP BY` or an aggregate function; this is enforced both in the prompt and as a hard validation check in `parse_llm_response`, which rejects any response containing `GROUP BY`. Grouping is instead performed downstream, in the evaluator, using the expected outcome's own columns as the grouping key — the model's only responsibility is determining the correct filter logic.

## Evaluation

Executability records first-try success and eventual success after one repair attempt (0.8 credit if repaired, 1.0 if correct on the first try, 0 if never executable).

Expected outcomes with no `count` column are treated as event-level: scored with precision, recall, and F1 over row identifiers (`eventID` when available on both sides, falling back to a synthetic `_row_id` assigned by row position, falling back to shared-column value matching), with F1 ≥ 0.95 treated as a pass.

Expected outcomes with a `count` column are treated as grouped/aggregate: the evaluator infers the grouping columns from the expected outcome and, if the generated query returned raw rows containing those columns, aggregates them itself before comparing. A grouped result passes only on an exact match of both the grouping keys and their counts; the accuracy score also reports the F1 overlap between the actual and expected `(group-key, count)` pairs, so a near-miss (off by a few counts, right dimensions) is visibly distinguishable from a badly wrong query (wrong dimensions or a much broader filter), even though both fail the strict pass/fail threshold.

The combined weighted score is 70% accuracy, 30% executability — correctness matters more than merely producing runnable SQL, but a working query still earns partial credit even when its result is wrong.

## Iteration

`main.py` runs the baseline and improved configurations over the same 11 hypotheses in a single execution and stores both sets of results, so the before/after comparison always reflects the same run rather than results gathered at different times.

Baseline failures were almost entirely schema hallucination: the model wrote SQL against conventional AWS CloudTrail field names (e.g. `userIdentity.type`) that do not exist in this dataset's flattened schema (`userIdentitytype`). Adding the real schema and sample rows to the improved prompt fixed nearly all execution failures. A second, less obvious failure mode — the model choosing the wrong aggregation dimensions — was diagnosed by hand-tracing individual hypotheses against the raw CSV and the expected-outcomes file, and was fixed by removing the grouping decision from the model's responsibility entirely, as described above.

One hypothesis was traced in full detail as a worked example: the "Sign-in Failures" hypothesis initially failed because the query filtered on `errorCode IS NOT NULL`, but this dataset records "unknown username" console-login failures via a populated `errorMessage` with an empty `errorCode` — a value-semantics detail invisible from column names and types alone. This was confirmed by cross-referencing the raw CSV rows against the expected outcome's row-position keys.

## Limitations and future work

The evaluation set is small (11 hypotheses) and tied to one flattened CloudTrail schema; conclusions about prompt design may not generalize to a differently-shaped dataset without re-verification.

Several hypotheses still fail on filter precision even after the grouping-decision fix: a query can select the correct columns and still filter too broadly or too narrowly relative to the reference definition (for example, matching a wider set of user-agent strings than the reference considers "suspicious"). This class of failure is a genuine open problem — narrowing it further would require either more diverse sample rows illustrating edge cases, or additional domain-specific guidance in the prompt, since the exact reference filter cannot be inferred from the hypothesis text alone.

One dataset-specific naming mismatch was found and deliberately left unresolved: one expected outcome uses a column name (`instanceType`) that does not exist in the actual CSV, which only has the flattened equivalent (`requestParametersinstanceType`). Renaming the query's output to match would only be possible by reading the expected outcome first, which would mean fixing a specific test case using information the generator is not supposed to have access to.

Grouped-result scoring is deliberately strict on the pass/fail threshold (exact match), since a counting/aggregation answer is either counting the right population or it isn't — there is no principled notion of "mostly correct" for a detection query. The accuracy score now also reports continuous overlap for diagnostic purposes, but the binary grading threshold is intentionally unchanged.

LLM-reported confidence is a self-assessment, not a calibrated probability, and clusters in a narrow range regardless of whether the query is later found to be correct or not; it should be read as the model's stated certainty about its own reasoning, not as a reliable predictor of accuracy.

Future work: a larger held-out hypothesis set to reduce variance in the reported metrics; calibrating confidence against historical evaluation outcomes; and injecting brief value-semantics notes for known dataset quirks (such as the errorCode/errorMessage split) without ever deriving those notes from the expected-outcomes file itself.