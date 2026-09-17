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
    
            
            return common + f"""
                Use only columns in this exact schema and write valid DuckDB SQL:
                {self.schema_description}
            """