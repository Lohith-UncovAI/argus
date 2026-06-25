class MockVisualAnalyzer:
    def __init__(self, fixture_map=None):
        self.fixture_map = fixture_map or {}

    async def literal_inventory(self, image, context):
        return self.fixture_map.get("literal_inventory", {"status": "SUCCESS", "items": []})

    async def analyze_instructions(self, image, context):
        return self.fixture_map.get("instructions", {"status": "SUCCESS", "attack_score": 0.0})

    async def analyze_deception(self, image, context):
        return self.fixture_map.get("deception", {"status": "SUCCESS", "deception_score": 0.0})

    async def verify_ocr_regions(self, image, observations, context):
        return self.fixture_map.get("ocr_verification", {"status": "SUCCESS", "verified": []})

    async def run_shadow_test(self, image, test_context):
        return self.fixture_map.get(
            "shadow_test",
            {
                "performed": True,
                "target_match": False,
                "canary_disclosed": False,
                "simulated_tool_call_attempted": False,
                "instruction_override_observed": False,
                "attacker_instruction_followed": False,
                "original_attack_score": 0.0,
                "reconstructed_attack_score": 0.0,
                "text_masked_attack_score": 0.0,
                "limitations": [],
            },
        )

