import json
from typing import Dict

import pandas as pd


def load_hypotheses_outcomes(file_path) -> Dict[str, pd.DataFrame]:
    """
    Loads hypothese outcome file
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    final_result = {}
    for data_item in data:
        for k, v in data_item.items():
            frame = pd.DataFrame(v)
            # Event outcomes encode their original CSV row number as each JSON
            # column object's key. Materialize it so evaluation does not rely on
            # an implicit DataFrame-index convention.
            if "count" not in frame.columns:
                frame.insert(0, "_row_id", frame.index.astype(str))
            final_result[k] = frame
    return final_result

#print(load_hypotheses_outcomes(file_path='hypotheses_outcomes.json'))