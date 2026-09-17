# Evaluation Report

## Summary

The improved system generated executable DuckDB SQL for all 11 hypotheses without requiring retries, increasing first-try and eventual execution rates to 100%. Five hypotheses matched their expected outcomes: root console access, CloudTrail disruption, Whoami reconnaissance, Secrets Manager access, and permanent access-key creation. Compared with the baseline, the accuracy pass rate increased from 27.27% to 45.45%, while the overall weighted score increased from 0.3818 to 0.6182.

The six remaining failures are result mismatches rather than SQL-generation or execution failures. 
1. Hypothesis 1 returns no results because failed console logins in this dataset are represented through `errorMessage` while the generated query checks `errorCode`. 
2. Hypotheses 4, 8, 9a, and 9b return broader result sets than their references because their filters capture additional error codes, bucket ACL calls, or user-agent values. 
3. Hypothesis 7 uses a lexicographic comparison for EC2 instance sizes, causing substantial over-selection and failing to produce the expected grouped `instanceType` counts.

The latest prompt generally returns complete event rows using `SELECT _row_id, *`. This improves explainability and allows the evaluator to normalize event-level output into grouped counts when the necessary columns are available. The remaining accuracy gap is therefore primarily caused by value semantics and filter breadth rather than hallucinated columns, invalid SQL, or missing result fields.

## Before and after

| Metric | Baseline | Improved |
|---|---:|---:|
| First Try Execution Rate | 0.6364 | 1.0000 |
| Eventual Execution Rate | 0.6364 | 1.0000 |
| Accuracy Pass Rate | 0.2727 | 0.4545 |
| Overall Weighted Score | 0.3818 | 0.6182 |

Executability measures valid DuckDB execution; a repaired query receives partial execution credit. Event results use precision, recall, and F1 over event identifiers, with F1 >= 0.95 treated as a pass. Grouped/count results require an exact match. The overall score weights accuracy at 70% and execution at 30%.

## Improved run by hypothesis

| ID | Hypothesis | Executed | Retried | Accuracy | Weighted score |
|---|---|---:|---:|---:|---:|
| 1 | CloudTrail logs contain failed console login attempts that could indicate brute force or bot attacks | True | False | 0.0000 | 0.3000 |
| 2 | Root user console login attempts can be identified in CloudTrail logs | True | False | 1.0000 | 1.0000 |
| 3 | Adversaries may attempt to disrupt CloudTrail logging to evade defenses | True | False | 1.0000 | 1.0000 |
| 4 | Unauthorized API calls (AccessDenied or UnauthorizedOperation errors) can reveal application errors or malicious activity | True | False | 0.0000 | 0.3000 |
| 5 | Attackers use GetCallerIdentity API calls (similar to Unix 'whoami' command) to identify which AWS account they're using | True | False | 1.0000 | 1.0000 |
| 6 | Adversaries may attempt to retrieve secrets (certificates, credentials, sensitive data) from AWS Secrets Manager | True | False | 1.0000 | 1.0000 |
| 7 | Attackers may attempt to launch extra-large EC2 instances (10xlarge or bigger) for cryptomining or other resource-intensive activities | True | False | 0.0000 | 0.3000 |
| 8 | Attackers may brute force S3 bucket names by attempting GetBucketAcl requests | True | False | 0.0000 | 0.3000 |
| 9a | CloudTrail logs contain requests from suspicious user agents (containing 'kali', 'parrot', or 'powershell') indicating potential attacker tools | True | False | 0.0000 | 0.3000 |
| 9b | CloudTrail logs contain requests from suspicious user agents (containing 'command/*') | True | False | 0.0000 | 0.3000 |
| 10 | CreateAccessKey events from IAM users (not roles) can identify creation of long-term credentials | True | False | 1.0000 | 1.0000 |

## Failure analysis

Observed failure categories: result_mismatch: 6.
The improved prompt addresses schema and syntax failures with exact schema grounding, examples, and one execution-error repair attempt. Result mismatches remain visible rather than being silently corrected with evaluation labels.

## Generated queries and explanations

### 1: Sign-in Failures (Brute Force/Bot Attacks)

**Interpretation:** This hypothesis is asking for CloudTrail entries that represent failed console login attempts, which could signal brute‑force or bot activity.

**Confidence:** 0.85

**Reasoning:** Failed console logins are recorded with eventName containing "ConsoleLogin" and a populated errorCode field. The query filters on those two conditions to capture only the relevant failures.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName ILIKE '%ConsoleLogin%' AND errorCode IS NOT NULL
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 2: Root Access Through Console

**Interpretation:** This hypothesis is asking for all CloudTrail log entries that represent console login attempts performed by the root user.

**Confidence:** 0.87

**Reasoning:** The query filters on the root identity type and the ConsoleLogin event name, using a case‑insensitive match to capture any variation of the event name.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userIdentitytype = 'Root' AND eventName ILIKE '%ConsoleLogin%'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 3: CloudTrail Disruption

**Interpretation:** This hypothesis is asking for any API calls that could modify or disable CloudTrail logging, such as deleting, updating, stopping, or creating a trail.

**Confidence:** 0.87

**Reasoning:** I filter on the eventName values that represent actions which would disrupt or alter CloudTrail logging, capturing all relevant records.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName IN ('DeleteTrail','UpdateTrail','StopLogging','PutTrail')
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 4: Unauthorized API Calls

**Interpretation:** This hypothesis is asking for all API calls that resulted in AccessDenied or UnauthorizedOperation errors, which may indicate unauthorized or malicious activity.

**Confidence:** 0.85

**Reasoning:** The query filters on the errorCode column for the two specified error types, using case-insensitive substring matching as required.

```sql
SELECT _row_id, * FROM cloudtrail WHERE errorCode ILIKE '%AccessDenied%' OR errorCode ILIKE '%UnauthorizedOperation%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 5: Whoami Reconnaissance

**Interpretation:** This hypothesis is asking for all API calls that retrieve the caller’s identity, analogous to a Unix whoami command.

**Confidence:** 0.87

**Reasoning:** The query filters on the specific eventName that represents the GetCallerIdentity API call, which returns the AWS account and user context.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetCallerIdentity'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 6: Secrets Manager Access

**Interpretation:** This hypothesis is asking for API calls that retrieve secrets from AWS Secrets Manager.

**Confidence:** 0.85

**Reasoning:** I filter on the Secrets Manager service and look for event names containing "GetSecret" to capture secret retrieval actions.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventSource = 'secretsmanager.amazonaws.com' AND eventName ILIKE '%GetSecret%'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 7: Large EC2 Instance Creation

**Interpretation:** This hypothesis is asking for EC2 instance launches of size 10xlarge or larger, which could indicate cryptomining or other heavy workloads.

**Confidence:** 0.85

**Reasoning:** The query filters for the RunInstances API call and selects instance types containing 'xlarge' that are lexicographically equal to or greater than '10xlarge', capturing 10xlarge and larger sizes.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'RunInstances' AND requestParametersinstanceType LIKE '%xlarge%' AND requestParametersinstanceType >= '10xlarge'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 8: S3 Bucket Brute Force

**Interpretation:** This hypothesis is asking for all GetBucketAcl API calls, which could indicate brute‑forcing of S3 bucket names.

**Confidence:** 0.87

**Reasoning:** The query filters on the specific eventName that represents an ACL lookup on a bucket, capturing every attempt regardless of source or outcome.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetBucketAcl'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 9a: Suspicious User Agents

**Interpretation:** This hypothesis is asking for CloudTrail events whose userAgent field contains any of the substrings 'kali', 'parrot', or 'powershell', which are commonly associated with attacker tools.

**Confidence:** 0.85

**Reasoning:** I used case‑insensitive substring matching (ILIKE) on the userAgent column to capture any log entry that includes the specified indicators, as required for a threat‑hunting query.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userAgent ILIKE '%kali%' OR userAgent ILIKE '%parrot%' OR userAgent ILIKE '%powershell%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 9b: Suspicious User Agents

**Interpretation:** This hypothesis is asking for all CloudTrail log entries whose userAgent field contains the substring 'command/' (case‑insensitive), indicating potentially suspicious command‑line activity.

**Confidence:** 0.85

**Reasoning:** I filter on the userAgent column using a case‑insensitive LIKE pattern to capture any occurrence of 'command/' in the string.

```sql
SELECT _row_id, * FROM cloudtrail WHERE lower(userAgent) LIKE '%command/%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 10: Permanent Key Creation

**Interpretation:** This hypothesis seeks to isolate CreateAccessKey API calls that were performed by IAM users rather than roles, indicating the creation of long‑term credentials.

**Confidence:** 0.85

**Reasoning:** The query filters on the specific event name and limits the identity type to IAMUser, which excludes role‑based identities such as AssumedRole or ServiceRole.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'CreateAccessKey' AND userIdentitytype = 'IAMUser'
```

**Result:** executed=True, passed=True, accuracy=1.0000


## Limitations

The evaluation set is small and comes from one CloudTrail dataset. Exact grouped-result matching is strict. LLM confidence is a self-assessment, not a calibrated probability.