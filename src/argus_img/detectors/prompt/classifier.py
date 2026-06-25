from typing import Dict


class NullPromptClassifier:
    async def classify(self, text: str, context) -> Dict[str, object]:
        return {"status": "NOT_TESTED", "state": "NOT_TESTED", "reason": "null_classifier"}


class MockPromptClassifier:
    async def classify(self, text: str, context) -> Dict[str, object]:
        lower = text.lower()
        score = 0.0
        if "ignore previous instructions" in lower:
            score = 0.95
        elif "prompt injection" in lower:
            score = 0.4
        return {"status": "SUCCESS", "score": score, "label": "prompt_injection" if score >= 0.5 else "benign"}


class ONNXPromptClassifier:
    async def classify(self, text: str, context) -> Dict[str, object]:
        return {"status": "UNSUPPORTED", "reason": "local ONNX model path not configured"}


class TransformersPromptClassifier:
    async def classify(self, text: str, context) -> Dict[str, object]:
        return {"status": "UNSUPPORTED", "reason": "local transformers model path not configured"}

