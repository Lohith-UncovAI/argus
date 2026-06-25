import re
from typing import Dict


def classify_text_context(text: str) -> str:
    lower = text.lower()
    active_command = re.search(
        r"\b(ignore\s+(all\s+)?(previous|prior|above)\s+instructions?|override\s+(the\s+)?(system|developer)|"
        r"(call|use|invoke)\s+(the\s+)?tool|run\s+(this\s+)?(command|shell|python)|execute\s+(this\s+)?command)\b",
        lower,
    )
    if re.search(r"['\"`].{0,80}(ignore|override|system prompt|call tool|run command|execute).{0,80}['\"`]", lower):
        return "quoted"
    if re.search(r"\b(attackers may write|attacker may write|do not follow|do not obey)\b.{0,120}\b(ignore|override|system prompt|call tool|run command|execute)\b", lower):
        return "discussed"
    if active_command:
        return "active"
    warning_markers = ["warning", "warns", "do not follow", "do not obey", "dangerous example"]
    discussion_markers = ["article", "discuss", "example", "sample", "quoted", "attackers may", "known as prompt injection"]
    if any(marker in lower for marker in warning_markers):
        return "warning"
    if any(marker in lower for marker in discussion_markers):
        return "discussed"
    return "active"


def extract_intent(text: str) -> Dict[str, object]:
    lower = text.lower()
    requested_action = None
    if any(term in lower for term in ["call tool", "use tool", "execute", "run command", "open file"]):
        requested_action = "tool_call"
    elif any(term in lower for term in ["send", "exfiltrate", "upload", "post to"]):
        requested_action = "data_exfiltration"
    return {
        "speaker_claim": "system" if "system" in lower else None,
        "requested_action": requested_action,
        "target": "credential" if any(term in lower for term in ["password", "api key", "token", "secret"]) else None,
        "authority_override": any(term in lower for term in ["ignore previous", "override", "developer message", "system prompt"]),
        "secrecy_requested": any(term in lower for term in ["do not tell", "secretly", "without telling"]),
        "data_exfiltration": any(term in lower for term in ["exfiltrate", "send to", "upload"]),
        "credential_request": any(term in lower for term in ["password", "api key", "token", "seed phrase", "private key"]),
        "quoted_or_active": classify_text_context(text),
    }
