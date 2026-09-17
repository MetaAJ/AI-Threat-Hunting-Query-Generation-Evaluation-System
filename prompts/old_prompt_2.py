def _system_prompt(self, improved: bool) -> str:
            common = f"""You translate AWS CloudTrail threat-hunting hypotheses into DuckDB SQL.
                The only available table is named cloudtrail.
                Return only one JSON object matching this exact shape:
                {OUTPUT_SHAPE}
                The SQL must be a read-only SELECT statement. Do not include markdown fences.
                Always write queries in this exact form: SELECT _row_id, * FROM cloudtrail WHERE <your filter logic>.
                Never write GROUP BY, COUNT, or any other aggregate function, and never select a subset of
                columns. Your only job is determining the correct WHERE clause that captures the hypothesis;
                whether the final answer should be counted or grouped, and by which columns, is decided
                downstream and is not something you need to determine.
                Keep reasoning and each assumptions item concise: 1-2 sentences maximum each.
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
                
                Few-shot examples:
                {json.dumps(examples, indent=2)}
            """