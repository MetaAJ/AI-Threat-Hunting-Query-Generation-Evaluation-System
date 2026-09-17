# Evaluation Report

## Before and after

| Metric | Baseline | Improved |
|---|---:|---:|
| First Try Execution Rate | 0.6364 | 0.9091 |
| Eventual Execution Rate | 0.6364 | 0.9091 |
| Accuracy Pass Rate | 0.2727 | 0.4545 |
| Overall Weighted Score | 0.3818 | 0.5909 |

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
| 7 | Attackers may attempt to launch extra-large EC2 instances (10xlarge or bigger) for cryptomining or other resource-intensive activities | False | True | 0.0000 | 0.0000 |
| 8 | Attackers may brute force S3 bucket names by attempting GetBucketAcl requests | True | False | 0.0000 | 0.3000 |
| 9a | CloudTrail logs contain requests from suspicious user agents (containing 'kali', 'parrot', or 'powershell') indicating potential attacker tools | True | False | 0.0000 | 0.3000 |
| 9b | CloudTrail logs contain requests from suspicious user agents (containing 'command/*') | True | False | 0.0000 | 0.3000 |
| 10 | CreateAccessKey events from IAM users (not roles) can identify creation of long-term credentials | True | False | 1.0000 | 1.0000 |

## Failure analysis

Observed failure categories: execution_error: 1, result_mismatch: 5.
The improved prompt addresses schema and syntax failures with exact schema grounding, examples, and one execution-error repair attempt. Result mismatches remain visible rather than being silently corrected with evaluation labels.

## Generated queries and explanations

### 1: Sign-in Failures (Brute Force/Bot Attacks)

**Interpretation:** This hypothesis is asking for failed console login attempts that may indicate brute force or bot attacks.

**Confidence:** 0.85

**Reasoning:** I filter on eventName containing 'ConsoleLogin' and require a non‑null errorCode, which CloudTrail records for failed login attempts.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName ILIKE '%ConsoleLogin%' AND errorCode IS NOT NULL
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 2: Root Access Through Console

**Interpretation:** This hypothesis is asking for events where the root user attempted to log in via the AWS console.

**Confidence:** 0.85

**Reasoning:** I filter on userIdentitytype='Root' to capture root user actions and use a case‑insensitive substring match on eventName to find console login attempts.

```sql
SELECT _row_id, * FROM cloudtrail WHERE userIdentitytype='Root' AND eventName ILIKE '%ConsoleLogin%'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 3: CloudTrail Disruption

**Interpretation:** This hypothesis is asking for CloudTrail API calls that could disable or alter logging, such as stopping, deleting, or updating a trail.

**Confidence:** 0.85

**Reasoning:** I filter on the CloudTrail service and the specific event names that represent disabling or modifying logging, which are the primary actions an adversary would use to disrupt logging.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventSource='cloudtrail.amazonaws.com' AND eventName IN ('StopLogging','DeleteTrail','UpdateTrail')
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 4: Unauthorized API Calls

**Interpretation:** This hypothesis is asking for events that resulted in AccessDenied or UnauthorizedOperation errors, indicating unauthorized API calls.

**Confidence:** 0.85

**Reasoning:** I filter on the errorCode column using case‑insensitive substring matches for the two error types specified in the hypothesis.

```sql
SELECT _row_id, * FROM cloudtrail WHERE errorCode ILIKE '%AccessDenied%' OR errorCode ILIKE '%UnauthorizedOperation%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 5: Whoami Reconnaissance

**Interpretation:** This hypothesis is asking for all CloudTrail events where attackers use the GetCallerIdentity API to discover the AWS account they are operating in.

**Confidence:** 0.85

**Reasoning:** I used a case‑insensitive substring match on eventName to capture any GetCallerIdentity calls, which are the API equivalent of a Unix whoami command.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName ILIKE '%GetCallerIdentity%'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 6: Secrets Manager Access

**Interpretation:** This hypothesis is asking for any API calls that retrieve secrets from AWS Secrets Manager.

**Confidence:** 0.85

**Reasoning:** I filter on the Secrets Manager service and look for event names containing "GetSecret" (case‑insensitive) to capture typical secret‑retrieval actions such as GetSecretValue, GetSecret, or similar.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventSource = 'secretsmanager.amazonaws.com' AND eventName ILIKE '%GetSecret%'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 7: Large EC2 Instance Creation

**Interpretation:** This hypothesis is asking for EC2 RunInstances events that launch instance types 10xlarge or larger, which could indicate cryptomining or other high‑resource activity.

**Confidence:** 0.85

**Reasoning:** I filter on the EC2 service and RunInstances action, then use a case‑insensitive regular expression via regexp_match to match any instance type with a size of 10xlarge or greater.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventSource='ec2.amazonaws.com' AND eventName='RunInstances' AND regexp_match(requestParametersinstanceType,'(?i)(10xlarge|12xlarge|16xlarge|24xlarge|32xlarge|48xlarge|64xlarge|96xlarge)')
```

**Result:** executed=False, passed=False, accuracy=0.0000

### 8: S3 Bucket Brute Force

**Interpretation:** This hypothesis is asking for any CloudTrail events where attackers might be trying to brute force S3 bucket names by sending GetBucketAcl requests.

**Confidence:** 0.85

**Reasoning:** I filter on eventName using a case‑insensitive substring match for 'GetBucketAcl', which captures all attempts to retrieve ACLs for any bucket, a common brute‑force technique.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName ILIKE '%GetBucketAcl%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 9a: Suspicious User Agents

**Interpretation:** This hypothesis is asking for CloudTrail events where the userAgent field contains indicators of suspicious tools such as Kali, Parrot, or PowerShell.

**Confidence:** 0.85

**Reasoning:** I used a case‑insensitive substring match on the userAgent column to capture any occurrence of the specified tool names, ensuring that variations in capitalization are included.

```sql
SELECT _row_id, * FROM cloudtrail WHERE lower(userAgent) LIKE '%kali%' OR lower(userAgent) LIKE '%parrot%' OR lower(userAgent) LIKE '%powershell%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 9b: Suspicious User Agents

**Interpretation:** This hypothesis is asking for CloudTrail events whose userAgent field contains the substring 'command/' (case‑insensitive), indicating potentially suspicious command‑line activity.

**Confidence:** 0.85

**Reasoning:** I used a case‑insensitive substring match on the userAgent column to capture any user agent that includes 'command/' regardless of case, as the hypothesis specifies a text field containing an indicator.

```sql
SELECT _row_id, * FROM cloudtrail WHERE lower(userAgent) LIKE '%command/%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 10: Permanent Key Creation

**Interpretation:** This hypothesis is asking for all CreateAccessKey events that were performed by IAM users (not roles).

**Confidence:** 0.85

**Reasoning:** I filter on eventName to capture only CreateAccessKey actions and on userIdentitytype to ensure the actor is an IAM user, excluding role-based identities.

```sql
SELECT _row_id, * FROM cloudtrail WHERE eventName='CreateAccessKey' AND userIdentitytype='IAMUser'
```

**Result:** executed=True, passed=True, accuracy=1.0000


## Limitations

The evaluation set is small and comes from one CloudTrail dataset. Exact grouped-result matching is strict. LLM confidence is a self-assessment, not a calibrated probability.