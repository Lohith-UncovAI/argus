class NullVisualAnalyzer:
    async def literal_inventory(self, image, context):
        return {"status": "NOT_TESTED", "state": "NOT_TESTED"}

    async def analyze_instructions(self, image, context):
        return {"status": "NOT_TESTED", "state": "NOT_TESTED"}

    async def analyze_deception(self, image, context):
        return {"status": "NOT_TESTED", "state": "NOT_TESTED"}

    async def verify_ocr_regions(self, image, observations, context):
        return {"status": "NOT_TESTED", "state": "NOT_TESTED"}

    async def run_shadow_test(self, image, test_context):
        return {
            "performed": False,
            "status": "NOT_TESTED",
            "limitations": ["real visual-language execution is not configured"],
        }

