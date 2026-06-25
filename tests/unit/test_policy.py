from argus_img.core.enums import EpistemicState, PolicyAction, UseProfile
from argus_img.core.models import DetectorFinding
from argus_img.policy.engine import PolicyEngine


def test_policy_blocks_confirmed_prompt_injection():
    finding = DetectorFinding(
        finding_id="finding:1",
        category="prompt_injection",
        type="instruction_override",
        state=EpistemicState.CONFIRMED,
        severity="critical",
        reason_codes=["PROMPT_INJECTION"],
    )
    decision = PolicyEngine.load_for_profile(UseProfile.AGENT_WITH_TOOLS).decide([finding])
    assert decision.action == PolicyAction.BLOCK
    assert decision.winning_rule_id == "block-confirmed-prompt-injection"
    assert decision.safe_claim is False


def test_policy_defaults_to_reconstructed_only_when_no_rules_match():
    decision = PolicyEngine.load_for_profile(UseProfile.AGENT_WITH_TOOLS).decide([])
    assert decision.action == PolicyAction.ALLOW_RECONSTRUCTED_ONLY
    assert decision.safe_claim is False
