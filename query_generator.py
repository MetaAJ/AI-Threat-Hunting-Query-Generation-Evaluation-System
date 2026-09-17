import json
import os
import re
import time
from typing import Any

from groq import BadRequestError, Groq, RateLimitError


OUTPUT_SHAPE = """{
  "sql": "SELECT ...",
  "interpretation": "This hypothesis is asking for...",
  "reasoning": "I structured the query this way because...",
  "assumptions": ["An explicit assumption"],
  "confidence": 0.85
}"""

OUTPUT_SCHEMA = {
    "name": "generated_query",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "sql": {"type": "string"},
            "interpretation": {"type": "string"},
            "reasoning": {"type": "string"},
            "assumptions": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "number"},
        },
        "required": ["sql", "interpretation", "reasoning", "assumptions", "confidence"],
        "additionalProperties": False,
    },
}


class QueryGenerator:
    """Generate explainable DuckDB SQL from a threat-hunting hypothesis."""
    
    def __init__(self, schema_description: str, model: str | None = None) -> None:
            self.schema_description = schema_description
            self.model = model or os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")


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

    def generate(self, hypothesis: str, *, improved: bool, previous: dict[str, Any] | None = None, 
                 execution_error: str | None = None) -> dict[str, Any]:
        
        messages = [
            {"role": "system", "content": self._system_prompt(improved)},
            {"role": "user", "content": f"Hypothesis: {hypothesis}"},
        ]
        if previous and execution_error:
            messages.extend([
                {"role": "assistant", "content": json.dumps(previous)},
                {
                    "role": "user",
                    "content": (
                        "The SQL failed in DuckDB with this error:\n"
                        f"{execution_error}\nFix it and return the full JSON object again."
                    ),
                },
            ])

        return parse_llm_response(call_llm(messages, self.model))

    


def call_llm(messages: list[dict[str, str]], model: str) -> str:
    """Single swappable boundary around the configured LLM client."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set")
    client = Groq(api_key=api_key, max_retries=0)
    working_messages = list(messages)
    json_retried = False
    for attempt in range(6):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=working_messages,
                temperature=0,
                max_completion_tokens=4000,
                reasoning_effort="low",
                response_format={"type": "json_schema", "json_schema": OUTPUT_SCHEMA},
            )
            return response.choices[0].message.content or ""
        except RateLimitError as exc:
            if attempt == 4:
                raise
            retry_after = exc.response.headers.get("retry-after")
            wait_seconds = float(retry_after) if retry_after else min(60, 5 * 2**attempt)
            print(f"    Groq rate limit reached; retrying in {wait_seconds:.1f}s")
            time.sleep(wait_seconds)
        except BadRequestError as exc:
            if json_retried or "json" not in str(exc).lower():
                raise
            json_retried = True
            working_messages = working_messages + [{
                "role": "user",
                "content": (
                    "Your previous response was incomplete. Return one complete JSON object "
                    "with all five required fields, including confidence. Keep reasoning concise."
                ),
            }]
            print("    Groq returned incomplete JSON; retrying once")

    raise RuntimeError("LLM request failed after rate-limit retries")


def parse_llm_response(raw_response: str) -> dict[str, Any]:
    cleaned = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", raw_response.strip())
    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM returned invalid JSON: {exc}") from exc

    required = {"sql", "interpretation", "reasoning", "assumptions", "confidence"}
    missing = required - result.keys()
    if missing:
        raise ValueError(f"LLM response is missing fields: {sorted(missing)}")
    if not isinstance(result["assumptions"], list):
        raise ValueError("LLM field 'assumptions' must be a list")
    if not 0 <= float(result["confidence"]) <= 1:
        raise ValueError("LLM confidence must be between 0 and 1")
    if not re.match(r"^\s*(WITH\b.*\bSELECT\b|SELECT\b)", result["sql"], re.I | re.S):
        raise ValueError("Only SELECT queries are allowed")
    return result
