# Evaluation Report

## Before and after

| Metric | Baseline | Improved |
|---|---:|---:|
| First Try Execution Rate | 0.6364 | 0.9091 |
| Eventual Execution Rate | 0.6364 | 0.9091 |
| Accuracy Pass Rate | 0.0909 | 0.2727 |
| Overall Weighted Score | 0.4295 | 0.6389 |

Executability measures valid DuckDB execution; a repaired query receives partial execution credit. Event results use precision, recall, and F1 over event identifiers, with F1 >= 0.95 treated as a pass. Grouped/count results require an exact match. The overall score weights accuracy at 70% and execution at 30%.

## Improved run by hypothesis

| ID | Hypothesis | Executed | Retried | Accuracy | Weighted score |
|---|---|---:|---:|---:|---:|
| 1 | CloudTrail logs contain failed console login attempts that could indicate brute force or bot attacks | True | False | 0.0000 | 0.3000 |
| 2 | Root user console login attempts can be identified in CloudTrail logs | True | False | 1.0000 | 1.0000 |
| 3 | Adversaries may attempt to disrupt CloudTrail logging to evade defenses | True | False | 0.0000 | 0.3000 |
| 4 | Unauthorized API calls (AccessDenied or UnauthorizedOperation errors) can reveal application errors or malicious activity | True | False | 0.8718 | 0.9103 |
| 5 | Attackers use GetCallerIdentity API calls (similar to Unix 'whoami' command) to identify which AWS account they're using | True | False | 1.0000 | 1.0000 |
| 6 | Adversaries may attempt to retrieve secrets (certificates, credentials, sensitive data) from AWS Secrets Manager | False | False | 0.0000 | 0.0000 |
| 7 | Attackers may attempt to launch extra-large EC2 instances (10xlarge or bigger) for cryptomining or other resource-intensive activities | True | False | 0.0000 | 0.3000 |
| 8 | Attackers may brute force S3 bucket names by attempting GetBucketAcl requests | True | False | 0.8870 | 0.9209 |
| 9a | CloudTrail logs contain requests from suspicious user agents (containing 'kali', 'parrot', or 'powershell') indicating potential attacker tools | True | False | 0.9950 | 0.9965 |
| 9b | CloudTrail logs contain requests from suspicious user agents (containing 'command/*') | True | False | 0.0000 | 0.3000 |
| 10 | CreateAccessKey events from IAM users (not roles) can identify creation of long-term credentials | True | False | 1.0000 | 1.0000 |

## Failure analysis

Observed failure categories: generation_error: 1, result_mismatch: 7.
The improved prompt addresses schema and syntax failures with exact schema grounding, examples, and one execution-error repair attempt. Result mismatches remain visible rather than being silently corrected with evaluation labels.

## Generated queries and explanations

### 1: Sign-in Failures (Brute Force/Bot Attacks)

**Interpretation:** This hypothesis is asking for console login attempts that did not succeed, which may signal brute‑force or bot activity.

**Confidence:** 0.88

**Reasoning:** ConsoleLogin events are the only API calls for console sign‑ins; a non‑null errorCode or an errorMessage containing "Failed" indicates a failed attempt. The filter captures all such failures regardless of the specific error code.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND (errorCode IS NOT NULL OR errorMessage ILIKE '%Failed%')
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 2: Root Access Through Console

**Interpretation:** This hypothesis asks for any CloudTrail events that represent console login attempts performed by the root IAM user.

**Confidence:** 0.88

**Reasoning:** Console login events are recorded with eventName 'ConsoleLogin'; filtering on userIdentitytype='Root' isolates attempts made by the root account.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND userIdentitytype = 'Root'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 3: CloudTrail Disruption

**Interpretation:** This hypothesis seeks events that indicate an adversary is trying to disrupt CloudTrail logging, such as deleting, updating, or stopping a trail, or any API call that results in an error.

**Confidence:** 0.85

**Reasoning:** I filter on event names that modify or control CloudTrail trails (containing 'Trail' or 'Logging') and also capture any event that produced an error code or an error message, which are typical signals of a disruption attempt.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName ILIKE '%Trail%' OR eventName ILIKE '%Logging%' OR errorCode IS NOT NULL OR errorMessage ILIKE '%error%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 4: Unauthorized API Calls

**Interpretation:** This hypothesis seeks events where an API call failed due to an access denial or unauthorized operation, which can indicate either application misconfiguration or malicious activity.

**Confidence:** 0.88

**Reasoning:** The query filters on both errorCode and errorMessage columns for the two common denial indicators, ensuring that any event reporting such an error is captured.

```sql
SELECT _row_id, * FROM cloudtrail WHERE (errorCode ILIKE '%AccessDenied%' OR errorCode ILIKE '%UnauthorizedOperation%' OR errorMessage ILIKE '%AccessDenied%' OR errorMessage ILIKE '%UnauthorizedOperation%')
```

**Result:** executed=True, passed=False, accuracy=0.8718

### 5: Whoami Reconnaissance

**Interpretation:** This hypothesis is asking for all API calls that retrieve the caller’s identity, analogous to a Unix whoami command.

**Confidence:** 0.88

**Reasoning:** The GetCallerIdentity eventName uniquely identifies the API used to discover the current AWS account and user context, so filtering on that eventName captures the relevant activity.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetCallerIdentity'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 6: Secrets Manager Access

**Interpretation:** Generation failed.

**Confidence:** 0.00

**Reasoning:** Unavailable.

```sql
-- No SQL generated
```

**Result:** executed=False, passed=False, accuracy=0.0000

### 7: Large EC2 Instance Creation

**Interpretation:** This hypothesis is asking for EC2 instance launch events that request instance types of 10xlarge or larger, which are often used for high‑performance or cryptomining workloads.

**Confidence:** 0.85

**Reasoning:** The requestParametersinstanceType column records the instance type requested during instance creation. Filtering on the specific large sizes captures the targeted activity without affecting other instance types.

```sql
SELECT _row_id, * FROM cloudtrail WHERE requestParametersinstanceType IN ('10xlarge','12xlarge','16xlarge','32xlarge')
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 8: S3 Bucket Brute Force

**Interpretation:** This hypothesis seeks S3 GetBucketAcl attempts that fail, which attackers might use to brute‑force bucket names.

**Confidence:** 0.85

**Reasoning:** Filtering on the specific API call and on common failure indicators captures the likely brute‑force attempts without aggregating or grouping.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetBucketAcl' AND (errorCode ILIKE '%NoSuchBucket%' OR errorCode ILIKE '%AccessDenied%')
```

**Result:** executed=True, passed=False, accuracy=0.8870

### 9a: Suspicious User Agents

**Interpretation:** This hypothesis seeks CloudTrail events whose userAgent strings contain indicators of known attacker tools or environments such as Kali Linux, Parrot OS, or PowerShell.

**Confidence:** 0.85

**Reasoning:** The query filters on the userAgent column using case‑insensitive substring matching for each keyword, capturing any event that logs a suspicious client agent.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userAgent ILIKE '%kali%' OR userAgent ILIKE '%parrot%' OR userAgent ILIKE '%powershell%'
```

**Result:** executed=True, passed=False, accuracy=0.9950

### 9b: Suspicious User Agents

**Interpretation:** This hypothesis is asking for any CloudTrail event whose userAgent string includes the substring 'command/', which is often used by malicious or suspicious tools.

**Confidence:** 0.85

**Reasoning:** I used a case‑insensitive LIKE to capture any occurrence of 'command/' in the userAgent column, ensuring that variations in capitalization are also matched.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userAgent ILIKE '%command/%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 10: Permanent Key Creation

**Interpretation:** This hypothesis seeks to identify CreateAccessKey API calls that were performed by IAM users rather than roles, indicating the creation of long‑term credentials.

**Confidence:** 0.88

**Reasoning:** The CreateAccessKey event name marks credential creation, and filtering on userIdentitytype='IAMUser' excludes role‑based calls. All columns are returned for further investigation.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'CreateAccessKey' AND userIdentitytype = 'IAMUser'
```

**Result:** executed=True, passed=True, accuracy=1.0000


## Limitations

The evaluation set is small and comes from one CloudTrail dataset. Exact grouped-result matching is strict. LLM confidence is a self-assessment, not a calibrated probability.