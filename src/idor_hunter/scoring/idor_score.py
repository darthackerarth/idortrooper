from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScoringContext:
    same_object: bool = False
    similarity: float = 0.0
    ownership_detected: bool = False
    ownership_field: str | None = None
    status_b: int = 0
    is_private: bool = False
    has_sensitive: bool = False
    identifier_consistent: bool = False
    is_error: bool = False
    is_unauthorized: bool = False
    is_forbidden: bool = False
    is_public: bool = False
    notes: list[str] = field(default_factory=list)


def compute_score(ctx: ScoringContext) -> tuple[int, list[str]]:
    """Compute a candidate score in [0, 100] and a list of evidence strings."""
    score = 0
    evidence: list[str] = []

    if ctx.same_object:
        score += 20
        evidence.append("Same object identifier referenced by both requests")

    if ctx.similarity >= 0.90:
        score += 20
        evidence.append(f"Very high response similarity ({ctx.similarity:.1%})")
    elif ctx.similarity >= 0.70:
        score += 10
        evidence.append(f"Moderate response similarity ({ctx.similarity:.1%})")

    if ctx.ownership_detected:
        score += 15
        if ctx.ownership_field:
            evidence.append(f"Ownership field preserved across responses ({ctx.ownership_field})")
        else:
            evidence.append("Ownership field preserved across responses")

    if 200 <= ctx.status_b < 300:
        score += 15
        evidence.append(f"Account B received 2xx status ({ctx.status_b})")

    if ctx.is_private:
        score += 10
        evidence.append("Object appears private")

    if ctx.has_sensitive:
        score += 10
        evidence.append("Response includes sensitive-looking fields")

    if ctx.identifier_consistent:
        score += 10
        evidence.append("Identifier consistent across both responses")

    if ctx.is_error:
        score -= 30
        evidence.append("Known error response pattern")

    if ctx.is_unauthorized:
        score -= 20
        evidence.append("Explicit unauthorized response")

    if ctx.is_forbidden:
        score -= 20
        evidence.append("Explicit forbidden response")

    if ctx.is_public:
        score -= 15
        evidence.append("Object appears public")

    score = max(0, min(100, score))
    return score, evidence


def classify(score: int) -> str:
    if score < 30:
        return "informational"
    if score < 50:
        return "low"
    if score < 70:
        return "medium"
    if score < 85:
        return "high"
    return "critical-candidate"
