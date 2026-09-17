# Evaluation Report

## Before and after

| Metric | Baseline | Improved |
|---|---:|---:|
| First Try Execution Rate | 0.7273 | 0.9091 |
| Eventual Execution Rate | 0.7273 | 0.9091 |
| Accuracy Pass Rate | 0.0909 | 0.3636 |
| Overall Weighted Score | 0.4743 | 0.7199 |

Executability measures valid DuckDB execution; a repaired query receives partial execution credit. Event results use precision, recall, and F1 over event identifiers, with F1 >= 0.95 treated as a pass. Grouped/count results require an exact match. The overall score weights accuracy at 70% and execution at 30%.

## Improved run by hypothesis

| ID | Hypothesis | Executed | Retried | Accuracy | Weighted score |
|---|---|---:|---:|---:|---:|
| 1 | CloudTrail logs contain failed console login attempts that could indicate brute force or bot attacks | True | False | 1.0000 | 1.0000 |
| 2 | Root user console login attempts can be identified in CloudTrail logs | True | False | 1.0000 | 1.0000 |
| 3 | Adversaries may attempt to disrupt CloudTrail logging to evade defenses | True | False | 0.2759 | 0.4931 |
| 4 | Unauthorized API calls (AccessDenied or UnauthorizedOperation errors) can reveal application errors or malicious activity | True | False | 0.8718 | 0.9103 |
| 5 | Attackers use GetCallerIdentity API calls (similar to Unix 'whoami' command) to identify which AWS account they're using | True | False | 1.0000 | 1.0000 |
| 6 | Adversaries may attempt to retrieve secrets (certificates, credentials, sensitive data) from AWS Secrets Manager | True | False | 0.0051 | 0.3036 |
| 7 | Attackers may attempt to launch extra-large EC2 instances (10xlarge or bigger) for cryptomining or other resource-intensive activities | False | True | 0.0000 | 0.0000 |
| 8 | Attackers may brute force S3 bucket names by attempting GetBucketAcl requests | True | False | 0.8797 | 0.9158 |
| 9a | CloudTrail logs contain requests from suspicious user agents (containing 'kali', 'parrot', or 'powershell') indicating potential attacker tools | True | False | 0.9950 | 0.9965 |
| 9b | CloudTrail logs contain requests from suspicious user agents (containing 'command/*') | True | False | 0.0000 | 0.3000 |
| 10 | CreateAccessKey events from IAM users (not roles) can identify creation of long-term credentials | True | False | 1.0000 | 1.0000 |

## Failure analysis

Observed failure categories: execution_error: 1, result_mismatch: 6.
The improved prompt addresses schema and syntax failures with exact schema grounding, examples, and one execution-error repair attempt. Result mismatches remain visible rather than being silently corrected with evaluation labels.

## Generated queries and explanations

### 1: Sign-in Failures (Brute Force/Bot Attacks)

**Interpretation:** This hypothesis is asking for CloudTrail events that represent failed attempts to log into the AWS console, which could signal brute‑force or bot activity.

**Confidence:** 0.88

**Reasoning:** Failed console logins are recorded with eventName 'ConsoleLogin' and include an errorCode or errorMessage when the attempt fails. The query filters on that event name and requires a non‑null error indicator.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND (errorCode IS NOT NULL OR errorMessage IS NOT NULL)
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 2: Root Access Through Console

**Interpretation:** This asks for all CloudTrail events where the root user attempted to log in via the AWS console.

**Confidence:** 0.88

**Reasoning:** The ConsoleLogin API call records console sign‑in attempts; filtering on eventName and userIdentitytype='Root' isolates root‑initiated attempts.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND userIdentitytype = 'Root'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 3: CloudTrail Disruption

**Interpretation:** This hypothesis is asking for any CloudTrail API calls that could modify or disable logging, such as creating, updating, deleting, or stopping a trail.

**Confidence:** 0.88

**Reasoning:** I filter on the CloudTrail service and the specific event names that represent actions which could disrupt logging. No error or success filter is added because the hypothesis focuses on the attempt itself, regardless of outcome.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventSource = 'cloudtrail.amazonaws.com' AND eventName IN ('DeleteTrail','UpdateTrail','StopLogging','PutTrail','CreateTrail')
```

**Result:** executed=True, passed=False, accuracy=0.2759

### 4: Unauthorized API Calls

**Interpretation:** This hypothesis seeks events where an API call was denied due to access or permission issues, which can indicate either legitimate application errors or potential malicious attempts.

**Confidence:** 0.85

**Reasoning:** The query checks both the errorCode and errorMessage columns for the two common denial indicators, ensuring that any record of an unauthorized or denied operation is captured.

```sql
SELECT _row_id, * FROM cloudtrail WHERE (errorCode ILIKE '%AccessDenied%' OR errorCode ILIKE '%UnauthorizedOperation%') OR (errorMessage ILIKE '%AccessDenied%' OR errorMessage ILIKE '%UnauthorizedOperation%')
```

**Result:** executed=True, passed=False, accuracy=0.8718

### 5: Whoami Reconnaissance

**Interpretation:** This hypothesis is asking for all API calls that retrieve the caller’s identity, analogous to a Unix whoami command.

**Confidence:** 0.92

**Reasoning:** The GetCallerIdentity eventName uniquely identifies the API used to discover the current AWS account and user context; no additional filters are needed.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetCallerIdentity'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 6: Secrets Manager Access

**Interpretation:** This hypothesis seeks events where an adversary might be reading secrets from AWS Secrets Manager.

**Confidence:** 0.88

**Reasoning:** Secrets Manager read operations are identified by the API calls GetSecretValue, ListSecrets, and GetSecretVersion; filtering on these event names captures potential secret retrieval activity.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName ILIKE 'GetSecretValue' OR eventName ILIKE 'ListSecrets' OR eventName ILIKE 'GetSecretVersion'
```

**Result:** executed=True, passed=False, accuracy=0.0051

### 7: Large EC2 Instance Creation

**Interpretation:** This query looks for EC2 launch events where the instance type is 10xlarge or larger, indicating potential cryptomining or other high‑resource activity.

**Confidence:** 0.85

**Reasoning:** It filters on the RunInstances API call and extracts the numeric prefix of any xlarge instance type using regexp_matches, then selects only those with a value of 10 or more.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'RunInstances' AND array_get(regexp_matches(requestParametersinstanceType, '([0-9]+)xlarge'),1) IS NOT NULL AND CAST(array_get(regexp_matches(requestParametersinstanceType, '([0-9]+)xlarge'),1) AS INTEGER) >= 10
```

**Result:** executed=False, passed=False, accuracy=0.0000

### 8: S3 Bucket Brute Force

**Interpretation:** This hypothesis seeks S3 GetBucketAcl attempts that resulted in an error, indicative of brute‑force bucket name guesses.

**Confidence:** 0.85

**Reasoning:** Filtering on the specific API call and requiring a non‑null errorCode captures failed attempts, which are the likely outcome of brute‑forcing bucket names.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetBucketAcl' AND errorCode IS NOT NULL
```

**Result:** executed=True, passed=False, accuracy=0.8797

### 9a: Suspicious User Agents

**Interpretation:** This hypothesis seeks CloudTrail events whose userAgent strings contain indicators of known attacker tools or shells such as Kali Linux, Parrot OS, or PowerShell.

**Confidence:** 0.85

**Reasoning:** The query filters on the userAgent column using case‑insensitive substring matching for each keyword, capturing any event that logs a suspicious client agent.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userAgent ILIKE '%kali%' OR userAgent ILIKE '%parrot%' OR userAgent ILIKE '%powershell%'
```

**Result:** executed=True, passed=False, accuracy=0.9950

### 9b: Suspicious User Agents

**Interpretation:** This hypothesis is asking for any CloudTrail event whose userAgent string includes the pattern 'command/*', indicating a potentially suspicious or non-standard client.

**Confidence:** 0.85

**Reasoning:** The query filters on the userAgent column using a case‑insensitive substring match to capture any occurrence of 'command/' followed by any characters, which is the indicator specified in the hypothesis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userAgent ILIKE '%command/%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 10: Permanent Key Creation

**Interpretation:** This hypothesis seeks events where an IAM user creates a new access key, indicating the generation of long‑term credentials.

**Confidence:** 0.88

**Reasoning:** The CreateAccessKey API call records key creation; filtering on userIdentitytype='IAMUser' excludes role‑based or service‑assumed identities.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'CreateAccessKey' AND userIdentitytype = 'IAMUser'
```

**Result:** executed=True, passed=True, accuracy=1.0000


## Limitations

The evaluation set is small and comes from one CloudTrail dataset. Exact grouped-result matching is strict. LLM confidence is a self-assessment, not a calibrated probability.