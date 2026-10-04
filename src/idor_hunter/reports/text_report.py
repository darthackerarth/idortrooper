from __future__ import annotations

from idor_hunter.models.finding import Finding


def render_text(finding: Finding) -> str:
    lines = [
        "idor-hunter report",
        f"method: {finding.method}",
        f"endpoint: {finding.endpoint}",
        f"score: {finding.score}",
        f"classification: {finding.classification}",
    ]
    if finding.object_candidate:
        oc = finding.object_candidate
        lines.append(f"object.value: {oc.value}")
        lines.append(f"object.type: {oc.object_type}")
        lines.append(f"object.location: {oc.location}")
        lines.append(f"object.confidence: {oc.confidence}")
    if finding.comparison:
        lines.append(f"comparison.status_a: {finding.comparison.get('status_a')}")
        lines.append(f"comparison.status_b: {finding.comparison.get('status_b')}")
        lines.append(f"comparison.similarity: {finding.comparison.get('similarity')}")
    if finding.ownership.get("detected"):
        lines.append(f"ownership.field: {finding.ownership.get('field')}")
    lines.append("evidence:")
    for e in finding.evidence:
        lines.append(f"  - {e}")
    lines.append(f"recommendation: {finding.recommendation}")
    return "\n".join(lines)
