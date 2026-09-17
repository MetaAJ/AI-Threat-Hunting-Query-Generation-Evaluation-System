# Evaluation Report

## Before and after

| Metric | Baseline | Improved |
|---|---:|---:|
| First Try Execution Rate | 0.5455 | 1.0000 |
| Eventual Execution Rate | 0.5455 | 1.0000 |
| Accuracy Pass Rate | 0.0909 | 0.4545 |
| Overall Weighted Score | 0.4022 | 0.7853 |

Executability measures valid DuckDB execution; a repaired query receives partial execution credit. Event results use precision, recall, and F1 over event identifiers, with F1 >= 0.95 treated as a pass. Grouped/count results pass only on an exact match of grouping columns and counts; the accuracy score for grouped results reports the F1 overlap between actual and expected groups, so a near-miss and a badly wrong query are distinguishable even though both fail the strict pass/fail threshold. The overall score weights accuracy at 70% and execution at 30%.

## Improved run by hypothesis

| ID | Hypothesis | Executed | Retried | Accuracy | Weighted score |
|---|---|---:|---:|---:|---:|
| 1 | CloudTrail logs contain failed console login attempts that could indicate brute force or bot attacks | True | False | 1.0000 | 1.0000 |
| 2 | Root user console login attempts can be identified in CloudTrail logs | True | False | 1.0000 | 1.0000 |
| 3 | Adversaries may attempt to disrupt CloudTrail logging to evade defenses | True | False | 1.0000 | 1.0000 |
| 4 | Unauthorized API calls (AccessDenied or UnauthorizedOperation errors) can reveal application errors or malicious activity | True | False | 0.8718 | 0.9103 |
| 5 | Attackers use GetCallerIdentity API calls (similar to Unix 'whoami' command) to identify which AWS account they're using | True | False | 1.0000 | 1.0000 |
| 6 | Adversaries may attempt to retrieve secrets (certificates, credentials, sensitive data) from AWS Secrets Manager | True | False | 0.0051 | 0.3036 |
| 7 | Attackers may attempt to launch extra-large EC2 instances (10xlarge or bigger) for cryptomining or other resource-intensive activities | True | False | 0.0000 | 0.3000 |
| 8 | Attackers may brute force S3 bucket names by attempting GetBucketAcl requests | True | False | 0.7544 | 0.8281 |
| 9a | CloudTrail logs contain requests from suspicious user agents (containing 'kali', 'parrot', or 'powershell') indicating potential attacker tools | True | False | 0.9950 | 0.9965 |
| 9b | CloudTrail logs contain requests from suspicious user agents (containing 'command/*') | True | False | 0.0000 | 0.3000 |
| 10 | CreateAccessKey events from IAM users (not roles) can identify creation of long-term credentials | True | False | 1.0000 | 1.0000 |

## Failure analysis

Observed failure categories: result_mismatch: 6.
The improved prompt addresses schema and syntax failures with exact schema grounding, examples, and one execution-error repair attempt. Result mismatches remain visible rather than being silently corrected with evaluation labels.

## Generated queries and explanations

### 1: Sign-in Failures (Brute Force/Bot Attacks)

**Interpretation:** This hypothesis asks for CloudTrail entries where a console login attempt failed, which may signal brute‑force or automated attacks.

**Confidence:** 0.90

**Reasoning:** Console login failures are recorded with eventName 'ConsoleLogin' and include an errorCode or errorMessage; filtering on those columns isolates only the unsuccessful attempts while returning all columns for further analysis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND (errorCode IS NOT NULL OR errorMessage IS NOT NULL)
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 2: Root Access Through Console

**Interpretation:** This hypothesis asks for any CloudTrail records of console login attempts made by the root account.

**Confidence:** 0.92

**Reasoning:** Console login events are recorded with the eventName 'ConsoleLogin'. The root principal is indicated by userIdentitytype = 'Root', so filtering on both captures the desired attempts.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND userIdentitytype = 'Root'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 3: CloudTrail Disruption

**Interpretation:** This hypothesis asks for any CloudTrail events that indicate a user tried to stop logging, delete a trail, or modify a trail configuration, which are typical actions used to disrupt CloudTrail logging.

**Confidence:** 0.88

**Reasoning:** CloudTrail management actions are emitted by the cloudtrail.amazonaws.com service. The three event names directly correspond to disabling logging, removing the trail, or changing its settings, so filtering on those captures the relevant attempts without adding unrelated conditions.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventSource = 'cloudtrail.amazonaws.com' AND (eventName = 'StopLogging' OR eventName = 'DeleteTrail' OR eventName = 'UpdateTrail')
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 4: Unauthorized API Calls

**Interpretation:** This hypothesis asks for any CloudTrail events that resulted in an AccessDenied or UnauthorizedOperation error, indicating a failed or unauthorized API call.

**Confidence:** 0.90

**Reasoning:** The query filters on the errorCode column for the two common error strings that represent denied or unauthorized operations, capturing the events of interest while returning all columns for further analysis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE (errorCode ILIKE '%AccessDenied%' OR errorCode ILIKE '%UnauthorizedOperation%')
```

**Result:** executed=True, passed=False, accuracy=0.8718

### 5: Whoami Reconnaissance

**Interpretation:** This hypothesis asks for any CloudTrail events where the GetCallerIdentity API was called, indicating an actor checking the current AWS account identity.

**Confidence:** 0.92

**Reasoning:** GetCallerIdentity is the specific API name used to retrieve the caller's AWS account information, so filtering on eventName captures those attempts without additional constraints.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetCallerIdentity'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 6: Secrets Manager Access

**Interpretation:** This hypothesis asks for any CloudTrail events where the Secrets Manager service was invoked to retrieve or view secret data.

**Confidence:** 0.88

**Reasoning:** Filtering on the Secrets Manager service and on event names containing 'Secret' captures actions such as GetSecretValue, DescribeSecret, or other secret‑related API calls without assuming a specific name, ensuring all retrieval attempts are included.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventSource = 'secretsmanager.amazonaws.com' AND eventName ILIKE '%Secret%'
```

**Result:** executed=True, passed=False, accuracy=0.0051

### 7: Large EC2 Instance Creation

**Interpretation:** This hypothesis asks for CloudTrail events where an EC2 instance launch request specifies a very large instance type (10xlarge or larger), which could indicate cryptomining or other high‑resource abuse.

**Confidence:** 0.88

**Reasoning:** The query filters on the requestParametersinstanceType column for any value containing 'xlarge' and further restricts to patterns that include sizes of 10xlarge or greater, capturing the targeted launch attempts while returning all columns for downstream analysis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE requestParametersinstanceType ILIKE '%xlarge' AND (requestParametersinstanceType ILIKE '%10xlarge%' OR requestParametersinstanceType ILIKE '%12xlarge%' OR requestParametersinstanceType ILIKE '%16xlarge%' OR requestParametersinstanceType ILIKE '%18xlarge%' OR requestParametersinstanceType ILIKE '%24xlarge%' OR requestParametersinstanceType ILIKE '%32xlarge%' OR requestParametersinstanceType ILIKE '%48xlarge%' OR requestParametersinstanceType ILIKE '%56xlarge%' OR requestParametersinstanceType ILIKE '%64xlarge%')
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 8: S3 Bucket Brute Force

**Interpretation:** This hypothesis asks for any CloudTrail events where an attacker tried to retrieve the ACL of an S3 bucket, which is a typical step in bucket‑name enumeration.

**Confidence:** 0.88

**Reasoning:** The GetBucketAcl API call is the only reliable indicator of a bucket‑ACL request; filtering on that event name captures all such attempts while returning every column for later analysis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetBucketAcl'
```

**Result:** executed=True, passed=False, accuracy=0.7544

### 9a: Suspicious User Agents

**Interpretation:** This hypothesis asks for any CloudTrail events where the userAgent string contains indicators of known attacker tools such as Kali Linux, Parrot OS, or PowerShell usage.

**Confidence:** 0.92

**Reasoning:** I filter on the userAgent column using case‑insensitive substring matches for each suspicious keyword, capturing any event that mentions those tools while returning all columns for further analysis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userAgent ILIKE '%kali%' OR userAgent ILIKE '%parrot%' OR userAgent ILIKE '%powershell%'
```

**Result:** executed=True, passed=False, accuracy=0.9950

### 9b: Suspicious User Agents

**Interpretation:** This hypothesis asks for any CloudTrail events where the userAgent string contains the pattern 'command/*', indicating a potentially suspicious client.

**Confidence:** 0.90

**Reasoning:** I filter on the userAgent column using ILIKE with a wildcard to capture any substring matching 'command/' regardless of case, returning all columns for further analysis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userAgent ILIKE '%command/%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 10: Permanent Key Creation

**Interpretation:** This hypothesis asks for events where an IAM user (as opposed to a role) creates a new access key, indicating the generation of long‑term credentials.

**Confidence:** 0.92

**Reasoning:** Filter on the specific API call CreateAccessKey and restrict to userIdentitytype equal to IAMUser to capture only user‑initiated key creation; all columns are returned for downstream analysis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName = 'CreateAccessKey' AND userIdentitytype = 'IAMUser'
```

**Result:** executed=True, passed=True, accuracy=1.0000


## Limitations

The evaluation set is small and comes from one CloudTrail dataset. Exact grouped-result matching is strict. LLM confidence is a self-assessment, not a calibrated probability.