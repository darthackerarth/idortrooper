from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Location = Literal["path", "query", "header", "json", "form", "cookie"]


@dataclass
class ObjectCandidate:
    value: str
    location: Location
    parameter_name: str | None
    object_type: str
    confidence: float
    context: str = ""

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "location": self.location,
            "parameter_name": self.parameter_name,
            "object_type": self.object_type,
            "confidence": round(self.confidence, 4),
            "context": self.context,
        }
