from idor_hunter.scoring.idor_score import ScoringContext, classify, compute_score


def test_high_candidate_score():
    ctx = ScoringContext(
        same_object=True,
        similarity=0.98,
        ownership_detected=True,
        ownership_field="ownerId",
        status_b=200,
        is_private=True,
        has_sensitive=True,
        identifier_consistent=True,
    )
    score, _ = compute_score(ctx)
    assert score >= 85
    assert classify(score) == "critical-candidate"


def test_forbidden_reduces_score():
    ctx = ScoringContext(
        same_object=True,
        similarity=0.1,
        status_b=403,
        is_forbidden=True,
    )
    score, _ = compute_score(ctx)
    assert score < 30
    assert classify(score) == "informational"


def test_not_found_reduces_score():
    ctx = ScoringContext(
        same_object=True,
        similarity=0.2,
        status_b=404,
        is_error=True,
    )
    score, _ = compute_score(ctx)
    assert score < 30
