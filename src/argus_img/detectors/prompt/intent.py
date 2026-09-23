import re
from typing import Dict

# Shared trigger-phrase fragment: what "an active attack command" looks like.
# Reused inside the quoted-text check below so that a trigger phrase quoted
# with surrounding punctuation (e.g. 'call the simulated tool send_email...')
# is recognised the same way whether or not it's wrapped in quote marks.
_TRIGGER_PHRASES = (
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|"
    r"override\s+(?:the\s+)?(?:system|developer)|"
    r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:context|instructions?)|"
    r"(?:call|use|invoke)\s+(?:the\s+)?(?:simulated\s+)?tool|"
    r"run\s+(?:this\s+)?(?:command|shell|python)|execute\s+(?:this\s+)?command|"
    r"(?:output|print|return|emit)\s+argus[-_\s]*canary)"
)
# A straight apostrophe is ambiguous between a real quote mark and an
# English contraction/possessive ("novel's", "don't"). Only treat it as a
# quote delimiter when it is NOT sitting directly between two word
# characters — that excludes contractions/possessives while still matching
# a real opening quote ('ignore ...) or closing quote (... instructions').
_QUOTE_OPEN = r"(?:[\"`]|(?<!\w)')"
_QUOTE_CLOSE = r"(?:[\"`]|'(?!\w))"
_QUOTED_TRIGGER_RE = re.compile(_QUOTE_OPEN + r".{0,80}" + _TRIGGER_PHRASES + r".{0,80}" + _QUOTE_CLOSE)
_ATTACKER_DISCUSSION_RE = re.compile(
    r"\b(attackers may write|attacker may write|do not follow|do not obey)\b.{0,120}\b(ignore|override|system prompt|call tool|run command|execute)\b"
)


def _ocr_normalize(lower: str) -> str:
    """Repair the OCR/typo mangling that most often defeats the marker checks:
    dropped spaces in common negation words ("donot"/"dont" -> "do not",
    "cannot" -> "can not") and collapsed whitespace. Deliberately conservative
    — only space-repair of function words, no semantic rewriting.
    """
    s = re.sub(r"\bdo\s*n['o]?t\b", "do not", lower)
    s = re.sub(r"\bcan\s*not\b", "can not", s)
    return re.sub(r"\s+", " ", s)


def classify_text_context(text: str) -> str:
    lower = _ocr_normalize(text.lower())
    if _QUOTED_TRIGGER_RE.search(lower):
        return "quoted"
    if _ATTACKER_DISCUSSION_RE.search(lower):
        return "discussed"
    # Discussion/warning markers are checked *before* falling back to the
    # active-command match below: text that both matches an active trigger
    # phrase and carries an explicit discussion/warning marker (e.g. "Known
    # as prompt injection, ... tells a model to disregard prior
    # instructions") is educational framing, not an active attack, and must
    # not be allowed to short-circuit past these markers.
    warning_markers = ["warning", "warns", "do not follow", "do not obey",
                       "dangerous example", "do not follow that", "do not obey that",
                       "any text in a photo", "any text in an image",
                       "embedded in an image", "embedded in images"]
    if any(marker in lower for marker in warning_markers):
        return "warning"
    # Strip email-like tokens (anything containing @) and bare domain names before
    # checking for "example" — prevents "audit@example.invalid" from matching the
    # "example" discussion marker.
    stripped = re.sub(r'\S+@\S*', '', lower)
    stripped = re.sub(r'\b\w+\.(com|org|net|io|invalid|example|localhost)\b', '', stripped)
    discussion_markers = ["article", "discuss", "example", "sample", "quoted",
                          "attackers may", "known as prompt injection"]
    if any(marker in stripped for marker in discussion_markers):
        return "discussed"
    return "active"


def extract_intent(text: str) -> Dict[str, object]:
    lower = text.lower()
    requested_action = None
    if any(term in lower for term in ["call tool", "use tool", "simulated tool", "execute", "run command", "open file", "send_email"]):
        requested_action = "tool_call"
    elif any(term in lower for term in ["send", "exfiltrate", "upload", "post to", "argus-canary", "argus_canary"]):
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
        r"\b(ignore\s+(previous|prior|all)\s+instructions?|disregard\s+(previous|prior|all)\s+(context|instructions?)|override\s+(system|developer)|"
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
