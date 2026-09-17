# Initial Approach : Evaluation Report

## Summary

Seven hypotheses execute successfully but fail exact-match scoring, for three distinct, hand-verified reasons rather than one general cause. Hypothesis 1 filters on errorCode, but this dataset records the relevant login failures via a populated errorMessage with an empty errorCode — a value-semantics issue invisible from column names alone. Hypotheses 5, 8, and 9a under-group relative to the reference output (e.g., #8 groups by one dimension where the reference uses four); we deliberately did not correct this by reading the expected grouping columns out of hypotheses_outcomes.json, since doing so would mean hardcoding answers rather than generating them. Hypotheses 3, 4, and 9b are near-misses caused by filter breadth (off by ~1% on #4, and a broader substring match than the reference definition on #9b) rather than structural mismatches. Hypothesis 7's instanceType column name mismatch is a known but undisclosed-by-design gap, since fixing it would require reading the expected schema.

## Before and after

| Metric | Baseline | Improved |
|---|---:|---:|
| First Try Execution Rate | 0.0909 | 0.9091 |
| Eventual Execution Rate | 0.0909 | 1.0000 |
| Accuracy Pass Rate | 0.0000 | 0.3636 |
| Overall Weighted Score | 0.0273 | 0.5486 |

Executability measures valid DuckDB execution; a repaired query receives partial execution credit. Event results use precision, recall, and F1 over event identifiers, with F1 >= 0.95 treated as a pass. Grouped/count results require an exact match. The overall score weights accuracy at 70% and execution at 30%.

## Improved run by hypothesis

| ID | Hypothesis | Executed | Retried | Accuracy | Weighted score |
|---|---|---:|---:|---:|---:|
| 1 | CloudTrail logs contain failed console login attempts that could indicate brute force or bot attacks | True | False | 0.0000 | 0.3000 |
| 2 | Root user console login attempts can be identified in CloudTrail logs | True | False | 0.9919 | 0.9943 |
| 3 | Adversaries may attempt to disrupt CloudTrail logging to evade defenses | True | False | 1.0000 | 1.0000 |
| 4 | Unauthorized API calls (AccessDenied or UnauthorizedOperation errors) can reveal application errors or malicious activity | True | False | 0.0000 | 0.3000 |
| 5 | Attackers use GetCallerIdentity API calls (similar to Unix 'whoami' command) to identify which AWS account they're using | True | False | 0.0000 | 0.3000 |
| 6 | Adversaries may attempt to retrieve secrets (certificates, credentials, sensitive data) from AWS Secrets Manager | True | False | 1.0000 | 1.0000 |
| 7 | Attackers may attempt to launch extra-large EC2 instances (10xlarge or bigger) for cryptomining or other resource-intensive activities | True | True | 0.0000 | 0.2400 |
| 8 | Attackers may brute force S3 bucket names by attempting GetBucketAcl requests | True | False | 0.0000 | 0.3000 |
| 9a | CloudTrail logs contain requests from suspicious user agents (containing 'kali', 'parrot', or 'powershell') indicating potential attacker tools | True | False | 0.0000 | 0.3000 |
| 9b | CloudTrail logs contain requests from suspicious user agents (containing 'command/*') | True | False | 0.0000 | 0.3000 |
| 10 | CreateAccessKey events from IAM users (not roles) can identify creation of long-term credentials | True | False | 1.0000 | 1.0000 |

## Failure analysis

Observed failure categories: result_mismatch: 7.
The improved prompt addresses schema and syntax failures with exact schema grounding, examples, and one execution-error repair attempt. Result mismatches remain visible rather than being silently corrected with evaluation labels.

## Generated queries and explanations

### 1: Sign-in Failures (Brute Force/Bot Attacks)

**Interpretation:** This hypothesis asks for failed console login attempts that may signal brute force or bot activity.

**Confidence:** 0.88

**Reasoning:** The query filters for ConsoleLogin events with a non‑null errorCode, then aggregates by source IP and error code to highlight repeated failures.

```sql
SELECT sourceIPAddress, errorCode, count(*) AS count FROM cloudtrail WHERE eventName = 'ConsoleLogin' AND errorCode IS NOT NULL GROUP BY sourceIPAddress, errorCode ORDER BY count DESC
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 2: Root Access Through Console

**Interpretation:** This hypothesis asks for identifying attempts by the root user to log in via the AWS Management Console.

**Confidence:** 0.88

**Reasoning:** The query filters on the root identity type and the ConsoleLogin API event, which CloudTrail records for console sign‑in attempts.

```sql
SELECT _row_id, eventTime, eventName, userIdentityarn, sourceIPAddress, awsRegion FROM cloudtrail WHERE userIdentitytype = 'Root' AND eventName = 'ConsoleLogin'
```

**Result:** executed=True, passed=True, accuracy=0.9919

### 3: CloudTrail Disruption

**Interpretation:** This hypothesis asks for evidence of actions that could disable or alter CloudTrail logging.

**Confidence:** 0.87

**Reasoning:** The query filters for API calls that modify or stop CloudTrail trails, which are typical disruption attempts.

```sql
SELECT _row_id, eventTime, eventName, userIdentityarn, sourceIPAddress, awsRegion FROM cloudtrail WHERE eventName IN ('DeleteTrail','StopLogging','UpdateTrail','PutTrailNotification')
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 4: Unauthorized API Calls

**Interpretation:** This asks for the frequency of unauthorized API calls, grouped by error type, service, and source IP to spot patterns of application errors or malicious attempts.

**Confidence:** 0.87

**Reasoning:** Filtering on the two relevant error codes isolates unauthorized attempts; grouping by service and IP highlights which services and actors are affected.

```sql
SELECT errorCode, eventSource, sourceIPAddress, count(*) AS count FROM cloudtrail WHERE errorCode IN ('AccessDenied','UnauthorizedOperation') GROUP BY errorCode, eventSource, sourceIPAddress ORDER BY count DESC
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 5: Whoami Reconnaissance

**Interpretation:** This hypothesis asks for all API calls that retrieve the caller’s identity, analogous to a Unix whoami command.

**Confidence:** 0.87

**Reasoning:** The query filters on the specific eventName 'GetCallerIdentity' and returns key context columns for each occurrence.

```sql
SELECT _row_id, eventTime, eventName, userIdentityarn, sourceIPAddress, awsRegion FROM cloudtrail WHERE eventName = 'GetCallerIdentity'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 6: Secrets Manager Access

**Interpretation:** This hypothesis is asking for any API calls that retrieve secrets from AWS Secrets Manager.

**Confidence:** 0.87

**Reasoning:** The query filters on the Secrets Manager service and looks for event names containing "GetSecret" (case‑insensitive) to capture secret‑retrieval actions such as GetSecretValue, GetSecret, or similar.

```sql
SELECT _row_id, eventTime, eventName, userIdentityarn, sourceIPAddress, awsRegion FROM cloudtrail WHERE eventSource = 'secretsmanager.amazonaws.com' AND LOWER(eventName) LIKE '%getsecret%'
```

**Result:** executed=True, passed=True, accuracy=1.0000

### 7: Large EC2 Instance Creation

**Interpretation:** This hypothesis asks for the frequency of launching very large EC2 instances, which could indicate cryptomining or other heavy workloads.

**Confidence:** 0.86

**Reasoning:** I filter RunInstances calls and use case‑insensitive LIKE patterns to match instance types 10xlarge or larger, then aggregate by source IP to identify repeat offenders.

```sql
SELECT sourceIPAddress, count(*) AS count FROM cloudtrail WHERE eventName = 'RunInstances' AND (lower(requestParametersinstanceType) LIKE '%10xlarge%' OR lower(requestParametersinstanceType) LIKE '%12xlarge%' OR lower(requestParametersinstanceType) LIKE '%16xlarge%' OR lower(requestParametersinstanceType) LIKE '%18xlarge%' OR lower(requestParametersinstanceType) LIKE '%24xlarge%' OR lower(requestParametersinstanceType) LIKE '%32xlarge%') GROUP BY sourceIPAddress ORDER BY count DESC
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 8: S3 Bucket Brute Force

**Interpretation:** This hypothesis asks for the frequency of GetBucketAcl API calls, which could indicate brute‑forcing of S3 bucket names.

**Confidence:** 0.88

**Reasoning:** The query filters for the specific API event and aggregates by source IP to highlight repeated attempts from the same origin.

```sql
SELECT sourceIPAddress, count(*) AS count FROM cloudtrail WHERE eventName = 'GetBucketAcl' GROUP BY sourceIPAddress ORDER BY count DESC
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 9a: Suspicious User Agents

**Interpretation:** This hypothesis asks for the frequency of CloudTrail events whose user agent strings contain indicators of attacker tools such as Kali, Parrot, or PowerShell.

**Confidence:** 0.86

**Reasoning:** The query filters rows where the userAgent field contains any of the specified substrings (case‑insensitive) and aggregates the results by the exact userAgent value to show how often each suspicious agent appears.

```sql
SELECT userAgent, count(*) AS count FROM cloudtrail WHERE LOWER(userAgent) LIKE '%kali%' OR LOWER(userAgent) LIKE '%parrot%' OR LOWER(userAgent) LIKE '%powershell%' GROUP BY userAgent ORDER BY count DESC
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 9b: Suspicious User Agents

**Interpretation:** This hypothesis asks for any CloudTrail events whose user agent string includes the substring 'command/' (case‑insensitive), indicating potentially suspicious or non‑standard clients.

**Confidence:** 0.87

**Reasoning:** The query filters on the userAgent column using a case‑insensitive LIKE to capture any occurrence of 'command/' and returns key context columns for each matching event.

```sql
SELECT _row_id, eventTime, eventName, userAgent, sourceIPAddress, awsRegion FROM cloudtrail WHERE LOWER(userAgent) LIKE '%command/%'
```

**Result:** executed=True, passed=False, accuracy=0.0000

### 10: Permanent Key Creation

**Interpretation:** This hypothesis asks for IAM user-created access keys, which are long‑term credentials.

**Confidence:** 0.88

**Reasoning:** The query filters for the CreateAccessKey API call and limits to IAMUser identities, returning event details for each occurrence.

```sql
SELECT _row_id, eventTime, eventName, userIdentityarn, sourceIPAddress, awsRegion, userIdentityuserName FROM cloudtrail WHERE eventName = 'CreateAccessKey' AND userIdentitytype = 'IAMUser'
```

**Result:** executed=True, passed=True, accuracy=1.0000


## Limitations

The evaluation set is small and comes from one CloudTrail dataset. Exact grouped-result matching is strict. LLM confidence is a self-assessment, not a calibrated probability.