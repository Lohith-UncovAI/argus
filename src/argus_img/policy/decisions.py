from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class PolicyRule:
    id: str
    priority: int
    when: Dict[str, Any]
    action: str
    summary: str = ""

