from __future__ import annotations

from idor_hunter.models.finding import Finding

BAR = "=" * 60


def _score_bar(score: int) -> str:
    filled = int(round(score / 100 * 30))
    return "[" + "█" * filled + "·" * (30 - filled) + "]"


def render_console(finding: Finding) -> str:
    lines: list[str] = []
    lines.append(BAR)
    lines.append(" IDOR HUNTER")
    lines.append(" Authorization Differential Analyzer")
    lines.append(BAR)
    lines.append("")

    lines.append("Endpoint")
    lines.append(f"  {finding.method} {finding.endpoint}")
    lines.append("")

    if finding.object_candidate:
        oc = finding.object_candidate
        lines.append("Object")
        lines.append(f"  {oc.value}")
        lines.append(f"  Location:   {oc.location}")
        if oc.parameter_name:
            lines.append(f"  Parameter:  {oc.parameter_name}")
        lines.append(f"  Type:       {oc.object_type}")
        lines.append(f"  Confidence: {oc.confidence:.0%}")
        lines.append("")

    cmp = finding.comparison
    if cmp:
        lines.append("Response comparison")
        lines.append(f"  Account A:   {cmp.get('status_a')}")
        lines.append(f"  Account B:   {cmp.get('status_b')}")
        sim = cmp.get("similarity", 0.0)
        lines.append(f"  Similarity:  {sim:.1%}")
        if cmp.get("json_similarity") is not None:
            lines.append(f"  JSON sim:    {cmp['json_similarity']:.1%}")
        lines.append("")

    if finding.ownership.get("detected"):
        lines.append("Ownership")
        lines.append(f"  Field: {finding.ownership.get('field')}")
        if finding.ownership.get("value_preview"):
            lines.append(f"  Value: {finding.ownership['value_preview']}")
        lines.append("")

    if finding.evidence:
        lines.append("Evidence")
        for e in finding.evidence:
            lines.append(f"  ✓ {e}")
        lines.append("")

    lines.append("Candidate score")
    lines.append(f"  {finding.score}/100  {_score_bar(finding.score)}")
    lines.append("")

    lines.append("Classification")
    lines.append(f"  {finding.classification.upper()}")
    lines.append("")

    lines.append("Important")
    lines.append("  This is an automated candidate assessment.")
    lines.append("  Manual validation is required.")
    lines.append(BAR)
    return "\n".join(lines)

