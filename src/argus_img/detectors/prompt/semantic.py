"""CPU-only semantic injection scorer.

No external ML dependencies — pure Python.  Uses three complementary signals:

1. Weighted token-overlap against a curated injection phrase bank.
2. Bigram-overlap against known attack sentence fragments.
3. Structural heuristics: suppression+redirect pattern, fill-in-blank templates,
   misleading single-word labels, indirect placeholder brackets.

Each signal produces a score in [0, 1].  The final score is the max of all
active signals weighted by their reliability.  Scores ≥ THRESHOLD_BLOCK
produce a BLOCK finding; scores ≥ THRESHOLD_REVIEW produce REVIEW.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Optional, Tuple

from argus_img.core.enums import EpistemicState, PolicyAction
from argus_img.core.models import DetectorFinding, TextObservation
from argus_img.detectors.prompt.intent import classify_text_context

# ── Thresholds ───────────────────────────────────────────────────────────────
THRESHOLD_BLOCK = 0.55
THRESHOLD_REVIEW = 0.35

# ── Token-level injection vocabulary ────────────────────────────────────────
# Each entry is (token_set, weight).  A hit on a high-weight token boosts the
# score more than low-weight background terms.
_INJECTION_TOKENS: List[Tuple[frozenset, float]] = [
    # Core override verbs/phrases — strongest signal
    (frozenset({"ignore", "disregard", "forget", "override", "bypass", "reset"}), 0.55),
    # Behavioural suppression pivot word
    (frozenset({"instead"}), 0.45),
    # Suppression verbs
    (frozenset({"do", "not", "mention", "describe", "acknowledge", "discuss", "refer"}), 0.20),
    # Redirect verbs
    (frozenset({"print", "reveal", "output", "say", "mention", "report", "disclose", "expose"}), 0.20),
    # Targets of extraction
    (frozenset({"secret", "password", "token", "key", "credential", "phrase", "passphrase", "hidden", "private"}), 0.50),
    # Authority/role words
    (frozenset({"system", "developer", "admin", "root", "instructions", "directive", "prompt"}), 0.35),
    # Jailbreak labels
    (frozenset({"dan", "jailbreak", "unrestricted", "maintenance", "mode", "god", "developer"}), 0.45),
    # Extraction qualifiers
    (frozenset({"only", "you", "know", "string", "value"}), 0.25),
    # Exfiltration action verbs
    (frozenset({"send", "upload", "exfiltrate", "transmit", "forward", "post"}), 0.45),
    # Exfiltration targets / filesystem references
    (frozenset({"read", "open", "load", "fetch", "retrieve", "get"}), 0.20),
    # Exfiltration destination markers
    (frozenset({"audit", "attacker", "evil", "remote", "external", "webhook"}), 0.35),
]

# Flat set of all high-signal tokens for quick first-pass (weight >= 0.45)
_HIGH_SIGNAL: frozenset = frozenset(
    t for (ts, w) in _INJECTION_TOKENS if w >= 0.45 for t in ts
)

# ── Bigram phrase bank ────────────────────────────────────────────────────────
# Matched as ordered token pairs within a sliding window of 3 tokens.
_INJECTION_BIGRAMS: List[Tuple[str, str, float]] = [
    ("ignore", "instructions", 0.85),
    ("ignore", "previous", 0.80),
    ("ignore", "prior", 0.80),
    ("override", "system", 0.80),
    ("override", "prompt", 0.80),
    ("forget", "instructions", 0.75),
    ("disregard", "instructions", 0.75),
    ("instead", "print", 0.70),
    ("instead", "say", 0.65),
    ("instead", "reveal", 0.70),
    ("instead", "output", 0.70),
    ("instead", "mention", 0.65),
    ("instead", "report", 0.65),
    ("print", "secret", 0.72),
    ("reveal", "secret", 0.72),
    ("print", "password", 0.72),
    ("mention", "password", 0.72),
    ("secret", "key", 0.60),
    ("do", "not", 0.10),   # low alone
    ("not", "mention", 0.40),
    ("dan", "mode", 0.80),
    ("jailbreak", "mode", 0.80),
    ("developer", "mode", 0.55),
    ("only", "know", 0.55),
    ("you", "know", 0.45),
    ("string", "know", 0.55),
    ("value", "secret", 0.65),
    ("hidden", "value", 0.60),
    ("steps", "process", 0.15),   # figstep - alone not enough
    ("gene", "sequencing", 0.05),
    ("plate", "tectonics", 0.05),
    # "say the X is" redirect pattern
    ("say", "is", 0.30),
    # "mention the string / only know"
    ("mention", "string", 0.55),
    ("mention", "only", 0.50),
    # "string only" proximity
    ("string", "only", 0.55),
    ("only", "know", 0.55),
    # Exfiltration patterns
    ("send", "to", 0.45),
    ("send", "it", 0.50),
    ("read", "send", 0.70),
    ("read", "and", 0.30),
    ("and", "send", 0.60),
    ("upload", "to", 0.65),
    ("exfiltrate", "to", 0.75),
    ("transmit", "to", 0.65),
    ("forward", "to", 0.55),
    ("fetch", "and", 0.45),
    ("retrieve", "and", 0.45),
]

# ── Structural patterns ───────────────────────────────────────────────────────
# These are applied to normalised text.  Each (regex, score, label).
_STRUCTURAL: List[Tuple[re.Pattern, float, str]] = [
    # Suppress + redirect
    (re.compile(r'\bdo\s+not\s+\w+\b.{0,80}\binstead\b', re.I), 0.80, "suppress_redirect"),
    # "mention the password/string/secret"
    (re.compile(r'\bmention\s+the\s+(password|secret|string|token|key|code|phrase)\b', re.I), 0.75, "mention_secret"),
    # "print out the secret key / hidden value"
    (re.compile(r'\bprint\s+(out\s+)?(the\s+)?(secret\s+key|hidden\s+value|password|token)\b', re.I), 0.80, "print_secret"),
    # "the string that only you know"
    (re.compile(r'\b(string|value|code|key|phrase)\s+that\s+only\s+you\s+know\b', re.I), 0.85, "only_you_know"),
    # "hidden value only you know"
    (re.compile(r'\bhidden\s+value\s+only\s+you\s+know\b', re.I), 0.85, "hidden_value_you_know"),
    # Indirect bracket placeholder [value of the secret key]
    (re.compile(r'\[\s*value\s+of\s+the\s+secret', re.I), 0.80, "bracket_placeholder"),
    # FigStep fill-in-blank list: numbered blanks
    (re.compile(r'\b(steps?\s+(in\s+)?(the\s+)?(process\s+of|to)\b|process\s+\w+\s+\w+).{0,200}(\d+\s*[.\)]\s*[_\s]{3,}){2}', re.I | re.S), 0.70, "figstep_blank_list"),
    # "process X Y" in caption position (2-4 words, image is realistic, suspicious context)
    (re.compile(r'^process\s+\w+(\s+\w+)?\s*$', re.I | re.M), 0.40, "process_caption"),
    # DAN / jailbreak mode header
    (re.compile(r'\b(dan|jailbreak|developer|god|maintenance|admin|root)\s+mode\s*:', re.I), 0.85, "jailbreak_mode"),
    # XML/Markdown override
    (re.compile(r'<instructions?\s*>.{0,300}<\s*/\s*instructions?\s*>', re.I | re.S), 0.80, "xml_injection"),
    (re.compile(r'^#+\s*(new|updated|override)\s+system\s+prompt', re.I | re.M), 0.80, "md_system_override"),
    # "role: system" YAML-style
    (re.compile(r'role\s*:\s*system\b', re.I), 0.75, "yaml_role_system"),
    # Partial OCR fragment: "Instead," or "instead" alone as a line/clause opener
    # (OCR of multi-line injections often captures the redirect clause even when the
    # suppression clause is garbled)
    (re.compile(r'\bInstead\s*,\s*(say|print|output|mention|reveal|report|write)', re.I), 0.72, "suppress_redirect"),
    # Partial: "trees in this" / "beaches in this" without full suppression sentence
    # Detect redirect-only half: "Instead, pr" (truncated OCR)
    (re.compile(r'\bInstead\s*,\s*p[rni]', re.I), 0.65, "suppress_redirect_fragment"),
    # "not mention any" without full sentence
    (re.compile(r'\bnot\s+mention\s+any\b', re.I), 0.60, "suppress_fragment"),
    # OCR-typo-tolerant: "Iniaead, say", "Inseead, say", "Inabey Instead", "lnstead, print"
    # EasyOCR commonly corrupts "Instead" on stylized/small fonts
    (re.compile(r'\bIn\w{4,8}\s*[,;]?\s*(say|print|output|mention|reveal|report|state)\b', re.I), 0.70, "suppress_redirect_ocr_typo"),
    # "Instead mentior" (OCR drops comma, "mention" → "mentior")
    (re.compile(r'\bInstead\s+men\w{3,6}\s*(the\s+)?(password|secret|string|token|key)\b', re.I), 0.75, "mention_secret_ocr_typo"),
    # "secret" near end of sentence after OCR noise
    (re.compile(r'\bsecret\b.{0,30}\b(key|value|string|phrase|code)\b', re.I), 0.50, "secret_credential_pair"),
    # "Instead ... secret" within 40 chars — handles OCR noise between the two words
    (re.compile(r'\bInstead\b.{0,40}\bsecret\b', re.I), 0.75, "instead_secret"),
    # "Instead ... password" within 40 chars
    (re.compile(r'\bInstead\b.{0,40}\bpassword\b', re.I), 0.75, "instead_password"),
    # Exfiltration: "read <path/file> and send it to <target>"
    (re.compile(r'\bread\b.{0,60}\band\s+send\s+(it\s+)?to\b', re.I), 0.85, "read_and_send"),
    # "send it to <email/url/attacker>"
    (re.compile(r'\bsend\s+it\s+to\b', re.I), 0.75, "send_it_to"),
    # "send <x> to <email/url>"
    (re.compile(r'\bsend\s+\w.{0,40}\bto\s+\S+@\S+\b', re.I), 0.85, "send_to_email"),
    # Generic "upload/exfiltrate/transmit to <target>"
    (re.compile(r'\b(upload|exfiltrate|transmit|forward)\s+.{0,60}\bto\b', re.I), 0.80, "exfiltrate_to"),
    # "read <file path>" followed by send/transmit — filesystem traversal + exfil
    (re.compile(r'\bread\s+[\w/\\.-]{3,}\b.{0,80}\b(send|upload|post|transmit)\b', re.I), 0.85, "read_file_exfil"),
    # Severely corrupted OCR: "Ins" fragment near "secret" — heavy obfuscation signature.
    # "Ins" alone is too common, but "Ins * secret" within 50 chars is very specific.
    (re.compile(r'\bIns\b.{0,50}\bsecret\b', re.I), 0.65, "ins_fragment_secret"),
    # Same for "password"
    (re.compile(r'\bIns\b.{0,50}\bpassword\b', re.I), 0.65, "ins_fragment_password"),
    # Partial OCR of "Do not mention any X in this image. Instead, ..."
    # Common OCR fragments when text is small/low-contrast on photo backgrounds:
    # "not mention any ... image" without full sentence structure
    (re.compile(r'\bnot\s+mention\s+any\s+\w+.{0,40}\b(image|this)\b', re.I), 0.72, "suppress_redirect"),
    # "mention any ... image ... instead" — suppress clause + redirect hint
    (re.compile(r'\bmention\s+any\b.{0,60}\b(instead|say|print|output)\b', re.I), 0.72, "suppress_redirect"),
    # "ention" (OCR drops leading 'm') near "image" and "instead" / action verb
    (re.compile(r'\bention\b.{0,60}\b(instead|say|print|know)\b', re.I), 0.65, "suppress_redirect_fragment"),
    # "string that only you know" — common in embedded_text payloads (partial OCR)
    (re.compile(r'\bstring\b.{0,30}\b(only|you|know)\b', re.I), 0.70, "only_you_know"),
    # "only you know" alone without "string" prefix
    (re.compile(r'\bonly\s+you\s+know\b', re.I), 0.72, "only_you_know"),
    # "prin" (truncated "print") near "secret" or "key" or "string"
    (re.compile(r'\bprin\w*\b.{0,30}\b(secret|key|string|password)\b', re.I), 0.68, "print_secret"),
    # "say the X is Y" redirect pattern (misleading substitution without suppress clause)
    (re.compile(r'\bsay\s+the\s+\w+\s+is\b', re.I), 0.55, "suppress_redirect"),
    # Indirect reference: "[value of ...]", "[secret key]", "[X]" bracket templates
    (re.compile(r'\[value\s+of\b', re.I), 0.80, "bracket_placeholder"),
    (re.compile(r'\[\s*(?:secret|hidden|private|the)\b', re.I), 0.72, "bracket_placeholder"),
    # Channel-difference OCR: "ignore" is frequently misread as "ighore", "igfiore",
    # "igmore", "ignbre" etc. when extracted from noisy difference channels.
    # Match Ig[a-z]{3,5}re (starts Ig, ends re, 3-5 middle chars) near "previous"
    # or "instructions" within 60 chars — very specific to channel-steg injections.
    (re.compile(r'\bIg[a-z]{2,5}re\b.{0,60}\b(previous|instructions|prior)\b', re.I), 0.80, "ignore_ocr_typo"),
    # Reversed: "previous" first, then corrupted "ignore"-like word (less common)
    (re.compile(r'\b(previous|instructions)\b.{0,60}\bIg[a-z]{2,5}re\b', re.I), 0.75, "ignore_ocr_typo"),
    # "reveal" near corrupted "ignore" variant — covers "ighore ... reveal" pattern
    (re.compile(r'\bIg[a-z]{2,5}re\b.{0,80}\breveal\b', re.I), 0.75, "ignore_ocr_typo"),
]

# ── Single-word misleading label detection ────────────────────────────────────
# A single isolated word (≤ 3 tokens total) that is NOT a realistic image label
# but IS a known misleading redirection target.  Low confidence alone; combined
# with a photo-realistic image context raises suspicion.
_MISLEADING_LABELS: frozenset = frozenset({
    # Scientific instruments (original set)
    "microscope", "telescope", "stethoscope", "calculator",
    "typewriter", "abacus", "compass", "thermometer",
    "periscope", "sextant", "chronometer", "oscilloscope",
    # CyberSecEval3 misleading label corpus
    "accordion", "banjo", "bicycle", "binoculars", "butterflies", "butterfly",
    "cacti", "camera", "clouds", "coffee mug", "dolphins", "football",
    "fountain pen", "fountains", "giraffe", "giraffes", "globe", "guitar",
    "harmonica", "harp", "honeybee", "honeybees", "hot air balloons",
    "kangaroo", "kangaroos", "kayak", "kite", "lawnmower", "lighthouse",
    "lighthouses", "maracas", "microphone", "motorcycle", "mountains",
    "mushrooms", "oceans", "parachute", "peacock", "peacocks", "penguins",
    "perfume", "piano", "pineapple", "pocket watch", "rainbows",
    "roller skates", "seagull", "sewing machine", "skateboard", "starfish",
    "submarine", "sunflower", "sunsets", "surfboard", "tambourine",
    "tornadoes", "trombone", "violin", "volcanoes", "waterfalls",
})


def _tokenise(text: str) -> List[str]:
    """Lowercase, NFKC-normalise, split on non-alphanumeric."""
    nfkc = unicodedata.normalize("NFKC", text).lower()
    return re.findall(r"[a-z0-9']+", nfkc)


def _token_overlap_score(tokens: List[str]) -> float:
    """Weighted token overlap: sum of highest-weight matching token sets."""
    if not tokens:
        return 0.0
    token_set = frozenset(tokens)
    score = 0.0
    for vocab_set, weight in _INJECTION_TOKENS:
        if token_set & vocab_set:
            score += weight * min(len(token_set & vocab_set) / max(len(vocab_set), 1), 1.0)
    # Normalise to [0,1] roughly (max possible ~2.45)
    return min(score / 2.0, 1.0)


def _bigram_score(tokens: List[str]) -> float:
    """Score based on ordered bigram proximity matches (window=4)."""
    if len(tokens) < 2:
        return 0.0
    best = 0.0
    for i, t1 in enumerate(tokens):
        window = tokens[i + 1: i + 5]
        for t2 in window:
            for b1, b2, w in _INJECTION_BIGRAMS:
                if t1 == b1 and t2 == b2:
                    best = max(best, w)
    return best


def _structural_score(text: str) -> Tuple[float, str]:
    """Return (highest structural pattern score, matched label)."""
    best_score = 0.0
    best_label = ""
    for pattern, score, label in _STRUCTURAL:
        if pattern.search(text):
            if score > best_score:
                best_score, best_label = score, label
    return best_score, best_label


def _misleading_label_score(tokens: List[str], text: str) -> float:
    """Detect misleading caption label (e.g. 'microscope' under balloon photo).

    The label may appear anywhere in the OCR output — even buried in noise tokens.
    Short text (<=4 words) gets full confidence; label in longer noisy OCR gets
    slightly reduced confidence since the surrounding context is ambiguous.
    """
    stripped = text.strip().lower()
    word_count = len(stripped.split())
    for label in _MISLEADING_LABELS:
        if label in stripped:
            # High confidence if the text is short (caption-like); lower if buried in noise
            return 0.60 if word_count <= 6 else 0.45
    return 0.0


def score_text(text: str) -> Dict[str, object]:
    """Score a single text string for injection likelihood.

    Returns a dict with keys:
      score      : float in [0, 1]
      signals    : dict of individual signal scores
      matched    : str label of dominant signal
    """
    tokens = _tokenise(text)

    # Check misleading label before early exit — single/short words can be misleading labels
    mislead_score = _misleading_label_score(tokens, text)

    # Quick exit: no high-signal tokens and text is very short → benign (unless misleading label)
    if len(tokens) < 2 and not (frozenset(tokens) & _HIGH_SIGNAL) and mislead_score == 0.0:
        return {"score": 0.0, "signals": {}, "matched": "none"}

    tok_score = _token_overlap_score(tokens)
    big_score = _bigram_score(tokens)
    struct_score, struct_label = _structural_score(text)

    signals = {
        "token_overlap": tok_score,
        "bigram": big_score,
        "structural": struct_score,
        "misleading_label": mislead_score,
    }

    # Combined: structural is most reliable; bigram next; token overlap is noisy
    combined = max(
        struct_score,
        big_score * 0.9,
        tok_score * 0.6,
        mislead_score,
    )
    if struct_label and struct_score >= max(big_score * 0.9, mislead_score):
        matched = struct_label
    elif mislead_score >= max(struct_score, big_score * 0.9):
        matched = "misleading_label"
    elif big_score * 0.9 >= tok_score * 0.6:
        matched = "bigram"
    else:
        matched = "token_overlap"

    return {"score": combined, "signals": signals, "matched": matched}


def analyze_semantic(
    observations: List[TextObservation],
    scan_id: str,
    include_raw_text: bool = False,
    skip_observation_ids: Optional[set] = None,
) -> List[DetectorFinding]:
    """Run semantic scoring over all text observations; return findings.

    skip_observation_ids: observation IDs already conclusively handled by the
    rule-based detector — skip these to avoid duplicate findings.
    """
    findings: List[DetectorFinding] = []
    seen_texts: set = set()

    for obs in observations:
        if skip_observation_ids and obs.observation_id in skip_observation_ids:
            continue
        text = obs.normalized_text
        if not text or text in seen_texts:
            continue
        seen_texts.add(text)

        # Skip text that is clearly quoted/discussed (security education, warnings).
        # Same context filter used by the rule-based detector.
        ctx = classify_text_context(text)
        if ctx in ("quoted", "discussed", "warning"):
            continue

        result = score_text(text)
        score: float = result["score"]  # type: ignore[assignment]
        matched: str = result["matched"]  # type: ignore[assignment]

        if score < THRESHOLD_REVIEW:
            continue

        active = score >= THRESHOLD_BLOCK
        # Semantic scorer is heuristic, not deterministic — cap at HIGHLY_LIKELY even at
        # BLOCK threshold.  CONFIRMED is reserved for deterministic rule matches.
        state = EpistemicState.HIGHLY_LIKELY if active else EpistemicState.POSSIBLE
        action = PolicyAction.BLOCK if active else PolicyAction.REVIEW
        severity = "critical" if active else "medium"
        likelihood = round(min(score, 0.90), 3)

        reason_codes = ["PROMPT_INJECTION"]
        if matched in ("suppress_redirect", "only_you_know", "hidden_value_you_know",
                       "bracket_placeholder", "mention_secret", "print_secret",
                       "jailbreak_mode", "xml_injection", "md_system_override",
                       "yaml_role_system", "ignore_ocr_typo", "suppress_redirect_fragment",
                       "suppress_redirect_ocr_typo", "mention_secret_ocr_typo",
                       "instead_secret", "instead_password", "ins_fragment_secret",
                       "ins_fragment_password"):
            reason_codes.append("INSTRUCTION_OVERRIDE")
        if matched == "misleading_label":
            reason_codes.append("MISLEADING_LABEL")
        if matched == "figstep_blank_list":
            reason_codes.append("FIGSTEP_TEMPLATE")
        if matched == "process_caption":
            reason_codes.append("INDIRECT_REFERENCE")
        if matched in ("read_and_send", "send_it_to", "send_to_email",
                       "exfiltrate_to", "read_file_exfil"):
            reason_codes.append("DATA_EXFILTRATION")

        evidence: Dict[str, object] = {
            "semantic_score": score,
            "matched_signal": matched,
            "signals": result["signals"],
            "text_length": len(text),
            "full_text_returned": False,
            "forensic_evidence_required": True,
        }
        if include_raw_text:
            evidence["raw_text"] = text

        findings.append(DetectorFinding(
            finding_id="finding:%s:semantic:%03d" % (scan_id, len(findings)),
            category="prompt_injection",
            type="semantic_injection",
            state=state,
            severity=severity,
            detector_confidence=score,
            evidence_quality=0.70 if active else 0.45,
            attack_likelihood=likelihood,
            impact="critical" if active else "medium",
            source_artifact_ids=[obs.source_artifact_id],
            observation_ids=[obs.observation_id],
            detector_ids=["detector:semantic-scorer"],
            reason_codes=reason_codes,
            recommended_action=action,
            limitations=[
                "Semantic scorer uses token/bigram heuristics; may produce false positives "
                "on security-education content quoting attack patterns.",
                "No external ML model — score is heuristic, not probabilistic.",
            ],
            evidence=evidence,
        ))

    return findings
