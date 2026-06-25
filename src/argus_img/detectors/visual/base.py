from pydantic import BaseModel


class ShadowTestReport(BaseModel):
    performed: bool
    target_match: bool = False
    target_model_id: str = "mock"
    canary_disclosed: bool = False
    simulated_tool_call_attempted: bool = False
    instruction_override_observed: bool = False
    attacker_instruction_followed: bool = False
    original_attack_score: float = 0.0
    reconstructed_attack_score: float = 0.0
    text_masked_attack_score: float = 0.0
    limitations: list = []

