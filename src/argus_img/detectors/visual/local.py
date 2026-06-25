class LocalVLMAnalyzer:
    def __init__(self, model_path):
        self.model_path = model_path

    async def literal_inventory(self, image, context):
        return {"status": "UNSUPPORTED", "reason": "real local VLM integration is deferred"}

    async def analyze_instructions(self, image, context):
        return {"status": "UNSUPPORTED", "reason": "real local VLM integration is deferred"}

    async def analyze_deception(self, image, context):
        return {"status": "UNSUPPORTED", "reason": "real local VLM integration is deferred"}

    async def verify_ocr_regions(self, image, observations, context):
        return {"status": "UNSUPPORTED", "reason": "real local VLM integration is deferred"}

    async def run_shadow_test(self, image, test_context):
        return {"performed": False, "status": "UNSUPPORTED", "reason": "real local VLM integration is deferred"}

