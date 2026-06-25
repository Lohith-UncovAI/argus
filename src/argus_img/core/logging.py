import json
import re
from typing import Any, Dict

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def sanitize_log_value(value: Any, max_len: int = 256) -> Any:
    if not isinstance(value, str):
        return value
    cleaned = _CONTROL.sub(lambda match: "\\u%04x" % ord(match.group(0)), value)
    if len(cleaned) > max_len:
        return cleaned[:max_len] + "...[truncated]"
    return cleaned


def json_log(event: str, **fields: Any) -> str:
    payload: Dict[str, Any] = {"event": sanitize_log_value(event)}
    payload.update({key: sanitize_log_value(value) for key, value in fields.items()})
    return json.dumps(payload, sort_keys=True, ensure_ascii=True)

