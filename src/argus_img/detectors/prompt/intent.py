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

    # Credential request: broad — covers direct naming AND extraction verbs near secret nouns.
    _cred_nouns = ["password", "api key", "api_key", "token", "seed phrase", "private key",
                   "secret key", "secret", "hidden value", "passphrase", "credential"]
    _extract_verbs = ["print", "reveal", "output", "say", "mention", "report", "show", "disclose",
                      "send", "upload", "expose", "repeat"]
    cred_noun_hit = any(term in lower for term in _cred_nouns)
    cred_verb_near = any(
        v in lower and any(n in lower for n in _cred_nouns)
        for v in _extract_verbs
    )
    credential_request = cred_noun_hit and (cred_verb_near or "only you know" in lower or "[value of" in lower)

    # Authority override: covers instruction suppression and redirect patterns too.
    authority_override = bool(re.search(
        r"\b(ignore\s+(previous|prior|all)\s+instructions?|override\s+(system|developer)|"
        r"do\s+not\s+mention\b|instead\s*(,\s*)?(print|say|output|reveal|mention|report)|"
        r"forget\s+(previous|prior|all)|disregard|reset\s+(your\s+)?instructions?)\b",
        lower,
    ))

    return {
        "speaker_claim": "system" if "system" in lower else None,
        "requested_action": requested_action,
        "target": "credential" if cred_noun_hit else None,
        "authority_override": authority_override,
        "secrecy_requested": any(term in lower for term in ["do not tell", "secretly", "without telling"]),
        "data_exfiltration": any(term in lower for term in ["exfiltrate", "send to", "upload"]),
        "credential_request": credential_request,
        "quoted_or_active": classify_text_context(text),
    }
