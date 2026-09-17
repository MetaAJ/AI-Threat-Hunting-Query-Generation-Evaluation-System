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
            Always write queries in this exact form: SELECT _row_id, * FROM cloudtrail WHERE <your filter logic>.
            Never write GROUP BY, COUNT, or any other aggregate function, and never select a subset of
            columns. Your only job is determining the correct WHERE clause that captures the hypothesis;
            whether the final answer should be counted or grouped, and by which columns, is decided
            downstream and is not something you need to determine.
            Keep reasoning and each assumptions item concise: 1-2 sentences maximum each.
            Explain the query using only the hypothesis and available data; never claim knowledge of expected results.
        """
        if not improved:
            return common

        examples = [
            {
                "hypothesis": "Find S3 object download events originating outside the primary region.",
                "output": {
                    "sql": "SELECT _row_id, * FROM cloudtrail WHERE eventName = 'GetObject' AND awsRegion <> 'us-east-1'",
                    "interpretation": "This asks for object-download activity from regions other than the account's primary region.",
                    "reasoning": "Filters on the named API event and excludes the expected primary region; every column is returned for downstream analysis.",
                    "assumptions": ["us-east-1 is treated as the expected primary region for this account."],
                    "confidence": 0.9,
                },
            },
            {
                "hypothesis": "Find Lambda function code updates.",
                "output": {
                    "sql": "SELECT _row_id, * FROM cloudtrail WHERE eventName = 'UpdateFunctionCode'",
                    "interpretation": "This asks for events where Lambda function code was modified.",
                    "reasoning": "A single, unambiguous event name identifies this action, so no additional filter is required.",
                    "assumptions": ["Every UpdateFunctionCode event represents a genuine code change."],
                    "confidence": 0.93,
                },
            },
        ]
        return common + f"""
            Use only columns in this exact schema and write valid DuckDB SQL:
            {self.schema_description}

            When checking for failed, erroneous, or unauthorized events, consider every column in the
            schema that could plausibly record an error or failure signal, rather than assuming it is
            always captured in one specific column.
            Do not combine unrelated conditions with OR unless the hypothesis explicitly describes multiple 
            alternative triggers. A broad OR condition (such as checking for any error) should only be added
            when the hypothesis is specifically about failures or errors, not appended to every query as a 
            general safety net.
            Prefer ILIKE '%text%' for substring or "contains an
            indicator" matching. If a regular expression is genuinely needed, DuckDB's function is
            regexp_matches(column, pattern) — not regexp_match.

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
    rate_limit_attempts = 0
    max_rate_limit_attempts = 5

    while True:
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
            if rate_limit_attempts >= max_rate_limit_attempts:
                raise
            retry_after = exc.response.headers.get("retry-after")
            wait_seconds = float(retry_after) if retry_after else min(60, 5 * 2**rate_limit_attempts)
            print(f"    Groq rate limit reached; retrying in {wait_seconds:.1f}s")
            time.sleep(wait_seconds)
            rate_limit_attempts += 1
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
    if re.search(r"\bGROUP\s+BY\b", result["sql"], re.I):
        raise ValueError("Query must not aggregate; return full event rows only")
    return result
