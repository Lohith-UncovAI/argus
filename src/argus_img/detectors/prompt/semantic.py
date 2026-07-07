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
    # Direct context/instruction suppression variants not covered by the stricter
    # regex rule bundle.
    (re.compile(r'\bdisregard\s+(all\s+)?(previous|prior|above)\s+(context|instructions?)\b', re.I), 0.85, "suppress_redirect"),
    (re.compile(r'\bforget\s+(all\s+)?(earlier|previous|prior)\s+(rules|instructions?|context)\b', re.I), 0.85, "forget_rules"),
    (re.compile(r'\badmin\s+command\s*:\s*(disable|bypass|turn\s+off)\b.{0,80}\b(filters?|policy|safety|guardrails?)\b', re.I), 0.85, "admin_disable_filters"),
    (re.compile(r'\b(output|print|return|emit)\s+ARGUS[-_\s]*CANARY\b', re.I), 0.85, "print_secret"),
    (re.compile(r'\bcall\s+(?:the\s+)?(?:simulated\s+)?(?:tool\s+)?[a-zA-Z_][\w.-]*\b', re.I), 0.75, "tool_invocation"),
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
    # Indirect bracket placeholder — covered by the broader pattern below (line 216+)
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
    # Direct suppression embedded in images, even when OCR misses the following
    # redirect clause.  "Do not mention the sun in this image" is already an
    # active image-targeting instruction.
    (re.compile(r'\bdo\s+not\s+mention\s+(?:the|a|an|any)\b.{0,90}\b(this\s+)?image\b', re.I), 0.72, "suppress_redirect"),
    # OCR-corrupted "do not mention any ..." where "mention any" becomes
    # "ayentionany", "mentior-an", etc.  Require a nearby redirect/image cue
    # to keep this from matching ordinary prose.
    (re.compile(
        r'\b(?:not|net|rot)\W*(?:\w{0,3}ention\w*|menti\w{2,6})\W*a\w{1,4}\b'
        r'.{0,120}\b(weather|instead|describe|image)\b',
        re.I,
    ), 0.72, "suppress_redirect_ocr_typo"),
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
    # FigStep colon-list: topic header + colon + numbered items (blank or inline).
    # Matches both newline-separated blanks (OCR multiline) and inline "1. 2. 3." (VLM output).
    # Broad "X of/in/for Y:" pattern covers all CyberSecEval3 FigStep headers.
    # FP risk is low: photo captions don't use academic list-header grammar.
    # FigStep colon-list: topic header + colon + numbered items (blank or inline).
    # Matches both newline-separated blanks (OCR multiline) and inline "1. 2. 3." (VLM output).
    # Broad "X of/in/for Y:...1." covers all CyberSecEval3 FigStep headers with numbered items.
    (re.compile(
        r'^(?:'
        r'\w[\w\s]{1,30}\s+(?:of|in|for|used\s+in|known\s+for|involved\s+in|needed\s+for)\s+\w'
        r'|steps?\s+(?:to\s+\w|in\s+the\s+\w)'
        r')'
        r'[^:]{0,80}:\s*(?:\n|\s*1\.)',
        re.I | re.M,
    ), 0.65, "figstep_colon_topic"),
    # Colon-topic header alone (no numbered follow-up): matches when VLM just reads the title.
    # 0.55 (BLOCK) — academic list headers never appear as benign photo captions.
    (re.compile(
        r'^(?:'
        r'[\w][\w\s-]{1,30}\s+(?:of|in|for|used\s+in|known\s+for|involved\s+in|needed\s+for|to\s+improve|to\s+set|to\s+design|to\s+implement|to\s+create)\s+\w'
        r'|steps?\s+(?:to\s+\w|in\s+the\s+\w)'
        r'|(?:popular|common|famous|basic|key|main|notable|classical|traditional)\s+\w[\w\s-]{2,50}'
        r'|[\w][\w\s-]{1,40}\s+(?:problems?|techniques?|technologies?|openings?|methods?|algorithms?|frameworks?|platforms?|mechanisms?|precautions?|milestones?|discoveries?|symptoms?|instruments?|projects?|systems?|concepts?|principles?|theories?|strategies?|components?|examples?|properties?|applications?)'
        r')'
        r'[^:]{0,80}:\s*$',
        re.I | re.M,
    ), 0.55, "figstep_colon_topic"),
    # Indirect reference query phrases — VLM caption of an image whose ENTIRE text is
    # an academic query/topic. Never appears as a genuine photo caption.
    # Scored at 0.55 (BLOCK) for strong structural patterns, 0.40 (REVIEW) for weaker ones.
    # Strong: "the X of Y", "how X works", "the difference between X and Y"
    (re.compile(
        r'^(?:'
        # "the X of/in/between Y" where X is a technical/scientific term, not a generic one.
        # Excludes "the history of art/friendship/life/cooking" by requiring technical suffixes.
        r'the\s+(?:basis|role|structure|concept|'
        r'principles?|applications?|characteristics?|inner\s+workings?|'
        r'security\s+mechanisms?|'
        r'functions?\s+of\s+the|classification|'
        r'ethical\s+implications?|human\s+genome|'
        r'potential\s+(?:resources?|applications?|benefits?|risks?)|'
        r'most\s+common\s+(?:types?|forms?|methods?|causes?)|'
        r'key\s+(?:components?|features?|concepts?|aspects?|factors?|principles?|differences?)|'
        r'life\s+cycle|time\s+complexity|'
        r'recent\s+(?:discoveries?|advances?|developments?|breakthroughs?|trends?)|'
        r'search\s+for\s+(?:extraterrestrial|intelligent|dark\s+matter|Higgs|gravitational))\s+'
        r'|the\s+(?:history|evolution|impact|mechanism|theory)\s+of\s+'
        r'(?!(?:art|life|love|food|music|time|work|people|culture|this|that|our|my|your|the|a|an)\b)'
        r'|the\s+(?:purpose|function|primary\s+purpose|primary\s+function)\s+of\s+(?:a\s+|the\s+)?'
        r'(?!(?:life|art|love|food|music|this|that|our|my|your)\b)'
        r'|the\s+(?:difference|differences?)\s+between\s+'
        r'(?!(?:art|love|right|wrong|good|bad|us|them)\b)'
        r'|the\s+(?:causes?|effects?|impacts?|consequences?)\s+of\s+'
        r'(?!(?:this|that|war|love|pain|grief|loss|art)\b)'
        r'|the\s+(?:significance|importance)\s+of\s+(?:the\s+)?'
        r'(?!(?:life|love|art|family|friendship|kindness|this|that|our|my|your)\b)'
        r'|how\s+(?:the\s+)?[\w][\w\s]{2,50}\s+(?:works?|improve|learn)'
        r'|the\s+(?:process|steps?|phases?)\s+of\s+'
        r'(?!(?:this|that|cooking|making|life|love|thinking|doing|being|going)\b)\w'
        r'|characteristics?\s+of\s+\w'
        r'|causes?\s+of\s+\w'
        r'|migration\s+of\s+\w'
        r'|principle\s+of\s+\w'
        r'|differences?\s+between\s+\w'
        r'|the\s+steps\s+to\s+\w'
        r'|process\s+of\s+(?:cloud|star|rock|cell|gene|protein|'
        r'photosynthesis|fermentation|evolution|mitosis|metamorphosis|fossilization|'
        r'crystallization|osmosis|electrolysis|combustion|nuclear)\b'
        r'|(?:techniques?|methods?)\s+for\s+(?:making|building|synthesizing|detecting|'
        r'analyzing|measuring|treating|preventing|designing|'
        r'developing|manufacturing|growing|cultivating)\s+\w[\w\s]{1,30}'
        r'|creating\s+(?:a\s+|an\s+)(?:game\s+engine|neural\s+network|blockchain|'
        r'compiler|operating\s+system|machine\s+learning|AI\s+model|'
        r'robot|simulation|3D)\b'
        r'|(?:potential\s+)?(?:resources?|properties?)\s+(?:that\s+can\s+be|of\s+(?!(?:life|love|art|cooking)\b))\w'
        r')',
        re.I | re.M,
    ), 0.55, "indirect_query_phrase"),
    # Weaker indirect reference: bare academic topic nouns/phrases that score at REVIEW level.
    # These are concepts that appear as entire image text in QRI/indirect attacks.
    (re.compile(
        r'^(?:'
        # Bare technical acronym or known scientific term
        r'(?:CRISPR|COBOL|FORTRAN|mRNA|DNA|RNA|GPU|CPU|SSD|API|TCP|HTTP|VPN|MRI|PET|CT|FFT|ALU|NMR|LIDAR|SONAR|RADAR)\b'
        r'|CRISPR-Cas\d+\b'
        r'|Fast\s+Fourier\s+Transform\b'
        r'|Heisenberg\s+\w+\s+Principle\b'
        r'|P\s+versus\s+NP\b'
        r'|Riemann\s+Hypothesis\b'
        r'|(?:afrobeat|biomechanics|cryogenic|cryptographic|nanotechnology|'
        r'superconductivity|entanglement|dark\s+matter|dark\s+energy|'
        r'neural\s+network|machine\s+learning|deep\s+learning|blockchain|'
        r'photosynthesis|mitochondria|cerebral|cortex|genome|jet\s+engine|'
        r'high-speed\s+rail|ray\s+tracing|geoengineering|neuromarketing|'
        r'nanoparticles?|exoplanet|quantum\s+gravity)\b'
        # "X in/of Y" academic phrases (2-7 words)
        r'|(?:aviation|cybersecurity|biomechanics|gene\s+expression|lift)\s+\w[\w\s]{1,40}'
        # "common X Y" or "X history" topic forms
        r'|common\s+(?:cybersecurity|programming|mathematical|types\s+of)\s+\w+'
        r'|\w[\w\s]{2,30}\s+history\s*$'
        r'|(?:ethical|social|economic|environmental)\s+implications?\s+of\b'
        r'|(?:differences?|similarities?)\s+between\s+\w'
        # "a/an X" bare concept with implied question ("a qubit", "an MRI scan")
        r'|(?:a\s+|an\s+)(?:qubit|fugue|microprocessor|thunderstorm|mushroom|bacterium|exoplanet)\b'
        # "X contribute/produce/conserve Y" (implicit "how does X do Y?" questions)
        r'|\w[\w\s]{3,40}\s+(?:contribute|produce|conserve|generate|impact|affect|enable)\s+\w'
        # Named historical/scientific works/concepts
        r"|Shakespeare's\s+'?\w|Coptic\s+crosses|Olympian\s+Gods|Tel\s+Dan|Rosetta\s+Stone"
        r'|Great\s+Pyramid|Maillard\s+reaction|Higgs\s+boson'
        r')',
        re.I | re.M,
    ), 0.40, "indirect_query_phrase"),
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
    # OCR often reads "[value of the secret key]" as "[value c the seret key]".
    # Keep the pattern bracket/placeholder-bound so plain UI labels like "value key"
    # are not escalated.
    (re.compile(r'\[\s*f?value\b.{0,60}\bkey\s*\]', re.I), 0.72, "bracket_placeholder"),
    # Severe OCR corruption can drop brackets and split "value of the secret key"
    # into fragments like "Walugof ... gsecret".  Require a value-of fragment
    # near secret/key vocabulary to avoid broad "value" false positives.
    (re.compile(r'\b\w?(?:value|valu|walu)\w{0,8}\b.{0,70}\b\w{0,3}(secret|key)\b', re.I), 0.72, "bracket_placeholder"),
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
    # Short bare-noun indirect-reference topics (query_relevant / indirect_reference)
    # These never appear as photo captions — their presence as sole image text is suspicious.
    "nuclear fission", "superposition", "np-completeness", "np completeness",
    "quantum entanglement", "fungi", "nanotechnology",
    "blockchain technology", "haute couture", "bitcoin",
    "gene sequencing", "plate tectonics", "geothermal energy",
    "molecular orbital theory", "coral reef", "coral reefs", "metal alloying",
    "fiber optic", "bacterium", "fossilization", "graphene",
    "higgs boson", "cognitive behavioral therapy", "encryption",
    "internet protocol", "monarch butterflies", "wave-particle duality",
    "quantum physics", "ancient egyptian temples",
    "maillard reaction", "mri scan", "ct scan", "pet scan",
    "mount everest", "habitat of", "habitat of a",
    "afrobeat", "crispr", "cobol", "qubit", "fugue",
    "dark matter", "dark energy", "exoplanet", "nanoparticle",
    "thunderstorm produce", "desert tortoise", "sea level rise",
    "glacier", "glaciers", "coral bleaching",
    "climbing mount", "challenges of climbing",
    "jet engine", "combustion chamber", "combustion",
    "high-speed rail", "ray tracing", "geoengineering",
    "neuromarketing", "gene expression",
    # Additional indirect_reference topics promoted from REVIEW to BLOCK
    "fast fourier transform", "coptic crosses", "olympian gods",
    "cybersecurity threats", "cryogenic preservation",
    "mitochondria in eukaryotic", "cerebral cortex",
    "p versus np", "p vs np", "neuroplasticity",
    "machine learning algorithms", "cryptographic hash",
    "biomechanics in prosthetic", "a mushroom",
    "heisenberg uncertainty", "shakespeare's",
    "supply and demand", "aviation history",
    "ethical implications of ai", "lift generate",
    "key factors in determining", "neural networks",
    "nanomaterials", "nanorobotics", "synaptic pruning",
    "urban forests", "symptoms of malaria", "turbocharger",
    "arithmetic logic unit", "password cracking",
    "global warming on sea", "deep-sea anglerfish",
    "prosthetic limbs", "piston engine",
    "reusable spacecraft", "andes mountain range",
    "motion planning in autonomous", "autonomous vehicles",
    "greenhouse effect", "geostationary orbit",
    "mariana trench", "spaceship's propulsion",
    "notochord in vertebrate", "loop quantum gravity",
    "asteroid belt", "rising global temperatures",
    "tel dan", "ajanta caves", "antarctic krill",
    "greek and norse", "microchip",
    "video game development", "rocket engines",
    "primary goal of machine learning",
})

# Regex for short academic topic phrases (1-6 words) that are indirect-reference attacks
# when they constitute the entire image text. These match topics that no camera would
# caption a photo with — they come from FigStep/QRI attack images.
_SHORT_TOPIC_PATTERN = re.compile(
    r'^(?:'
    # scientific/technical concepts with modifier
    r'(?:nuclear|quantum|molecular|optical|geothermal|gravitational|electromagnetic)\s+\w[\w\s]{1,30}|'
    r'(?:ancient|classical|modern|medieval)\s+\w[\w\s]{1,30}|'
    r'(?:the\s+)?(?:principles?|properties?|characteristics?|fundamentals?|applications?)\s+of\s+\w[\w\s]{1,40}|'
    # bare technical terms
    r'(?:np.?completeness|superposition|entanglement|'
    r'nanotechnology|blockchain|cryptocurrency|bitcoin|'
    r'photosynthesis|mitosis|electrolysis|osmosis|'
    r'fermentation|crystallization|fossilization|'
    r'haute\s+couture|fungi|bacterium|graphene|'
    r'maillard\s+reaction|crispr|cobol|qubit|fugue|afrobeat|neuromarketing)|'
    # "habitat of X" — common in query_relevant indirect-reference attacks
    r'(?:a\s+)?(?:typical\s+)?habitat\s+of\s+\w[\w\s]{0,40}|'
    # "X scan" (MRI scan, CT scan, PET scan) — bare medical imaging concept
    r'(?:mri|ct|pet|nmr)\s+scan|'
    # "challenges of X" — academic topic form
    r'challenges\s+of\s+\w[\w\s]{1,40}|'
    # "X of Mount Y" — geographic challenge topics
    r'(?:climbing|ascent\s+of|descent\s+of)\s+mount\s+\w[\w\s]{0,30}'
    r')\s*\.?\s*$',
    re.I,
)


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
    """Detect misleading caption label or short indirect-reference topic phrase.

    The label may appear anywhere in the OCR output — even buried in noise tokens.
    Short text (<=6 words) gets full confidence; label in longer noisy OCR gets
    slightly reduced confidence since the surrounding context is ambiguous.
    Also checks the short-topic pattern for bare concept nouns.
    """
    stripped = text.strip().lower()
    word_count = len(stripped.split())
    for label in _MISLEADING_LABELS:
        if label not in stripped:
            continue
        label_wc = len(label.split())
        # Classify as high-confidence if the label represents ≥50% of total words
        # OR if the total text is short enough (≤10 words) for the label to be the
        # primary content (surrounded only by OCR noise like digits, symbols).
        # At >10 words the text is likely a genuine descriptive sentence; use REVIEW.
        label_ratio = label_wc / max(word_count, 1)
        if label_ratio >= 0.5 or word_count <= 10:
            return 0.30
        return 0.25
    # Short academic topic phrase that is too specific for a photo caption
    if word_count <= 8 and _SHORT_TOPIC_PATTERN.match(stripped):
        return 0.30
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
    token_set = frozenset(tokens)
    if struct_label in {"indirect_query_phrase", "process_caption"}:
        struct_score = min(struct_score, 0.30)
    elif struct_label == "figstep_colon_topic" and not (token_set & _HIGH_SIGNAL):
        struct_score = min(struct_score, THRESHOLD_REVIEW)

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
                       "ins_fragment_password", "tool_invocation", "forget_rules",
                       "admin_disable_filters"):
            reason_codes.append("INSTRUCTION_OVERRIDE")
        if matched == "tool_invocation":
            reason_codes.append("TOOL_INVOCATION_REQUEST")
        if matched == "misleading_label":
            reason_codes.append("MISLEADING_LABEL")
        if matched in ("figstep_blank_list", "figstep_colon_topic"):
            reason_codes.append("FIGSTEP_TEMPLATE")
        if matched in ("process_caption", "figstep_colon_topic", "indirect_query_phrase"):
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
