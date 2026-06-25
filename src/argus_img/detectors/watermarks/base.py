from pydantic import BaseModel

from argus_img.core.enums import WatermarkState


class WatermarkDetection(BaseModel):
    scheme_id: str
    state: WatermarkState
    confidence: float = 0.0
    evidence: dict = {}

