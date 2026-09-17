def _system_prompt(self, improved: bool) -> str:
            common = f"""You translate AWS CloudTrail threat-hunting hypotheses into DuckDB SQL.
                The only available table is named cloudtrail.
                Return only one JSON object matching this exact shape:
                {OUTPUT_SHAPE}
                The SQL must be a read-only SELECT statement. Do not include markdown fences.
                For event-level queries, include _row_id in SELECT so results can be evaluated.
                For grouped queries, name the count column count.
                Keep reasoning and each assumptions item concise: 1-2 sentences maximum each.
                For broad or repeated behavioral patterns, aggregate by the smallest useful set of context
                columns (such as event, identity, source IP, user agent, or error) and return count.
                When the hypothesis says a text field contains an indicator, use a case-insensitive substring
                comparison instead of exact equality.
                Explain the query using only the hypothesis and available data; never claim knowledge of expected results.
            """
            
            if not improved:
                return common
    
            examples = [
                {
                    "hypothesis": "Count EC2 instance-description activity by region.",
                    "output": {
                        "sql": "SELECT awsRegion, count(*) AS count FROM cloudtrail WHERE eventName = 'DescribeInstances' GROUP BY awsRegion ORDER BY count DESC",
                        "interpretation": "This asks for the regional distribution of EC2 instance-description calls.",
                        "reasoning": "The query filters the named API event and groups matching calls by AWS region.",
                        "assumptions": ["Each matching log row represents one API call."],
                        "confidence": 0.94,
                    },
                },
                {
                    "hypothesis": "Find IAM policy-change events made by root identities.",
                    "output": {
                        "sql": "SELECT _row_id, eventTime, eventName, userIdentityarn, sourceIPAddress, awsRegion FROM cloudtrail WHERE userIdentitytype = 'Root' AND eventName IN ('PutUserPolicy', 'AttachUserPolicy')",
                        "interpretation": "This asks for root-user activity that changes IAM permissions.",
                        "reasoning": "The query combines the root identity type with two policy-changing API events.",
                        "assumptions": ["The named events represent the policy changes relevant to this example."],
                        "confidence": 0.88,
                    },
                },
                {
                    "hypothesis": "Count failed requests by error code and service.",
                    "output": {
                        "sql": "SELECT errorCode, eventSource, count(*) AS count FROM cloudtrail WHERE errorCode IS NOT NULL GROUP BY errorCode, eventSource ORDER BY count DESC",
                        "interpretation": "This asks for the distribution of unsuccessful API calls across AWS services.",
                        "reasoning": "A populated errorCode marks failed calls, which are grouped by error and service.",
                        "assumptions": ["Rows with a non-null errorCode are treated as failed requests."],
                        "confidence": 0.92,
                    },
                },
            ]
            
            return common + f"""
                Use only columns in this exact schema and write valid DuckDB SQL:
                {self.schema_description}
                
                If the hypothesis describes a pattern of repeated or frequent behavior across many actors
                (for example brute force, scanning, or repeated failures), prefer a grouped query that counts
                occurrences by the relevant dimension such as source IP, user identity, or error code. If the
                hypothesis asks to identify specific events or actors, return event-level rows with _row_id.
                
                Few-shot examples:
                {json.dumps(examples, indent=2)}
            """