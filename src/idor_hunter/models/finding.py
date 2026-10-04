from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from idor_hunter.models.object import ObjectCandidate


@dataclass
class Finding:
    severity: str
    confidence: float
    endpoint: str
    method: str
    object_candidate: ObjectCandidate | None
    evidence: list[str] = field(default_factory=list)
    comparison: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    score: int = 0
    classification: str = "informational"
    ownership: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "endpoint": self.endpoint,
            "method": self.method,
            "object_candidate": self.object_candidate.to_dict() if self.object_candidate else None,
            "evidence": list(self.evidence),
            "comparison": dict(self.comparison),
            "recommendation": self.recommendation,
            "score": self.score,
            "classification": self.classification,
            "ownership": dict(self.ownership),
        }
