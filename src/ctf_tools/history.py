import json
from pathlib import Path
from typing import Any, Dict

HISTORY_PATH = Path.home() / ".ctf_tools_history.jsonl"


def log_event(action: str, payload: Dict[str, Any]) -> None:
    """
    Append a simple JSON line to history for traceability.
    """
    record = {"action": action, **payload}
    try:
        with HISTORY_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        # History failures should not break core functionality.
        pass
