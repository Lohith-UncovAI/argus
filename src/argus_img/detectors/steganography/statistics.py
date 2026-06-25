from pathlib import Path
from typing import Dict

from PIL import Image


def image_entropy_summary(path: Path) -> Dict[str, float]:
    with Image.open(path) as image:
        gray = image.convert("L")
        hist = gray.histogram()
    total = float(sum(hist)) or 1.0
    import math

    entropy = -sum((count / total) * math.log(count / total, 2) for count in hist if count)
    return {"grayscale_entropy": entropy}

