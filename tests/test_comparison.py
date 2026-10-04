from idor_hunter.compare.similarity import compare_responses
from idor_hunter.parser.raw_http import parse_raw_response


def _resp(status: int, body: str, content_type: str = "application/json"):
    raw = (
        f"HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\n\r\n{body}"
    )
    return parse_raw_response(raw)


def test_high_similarity_identical():
    a = _resp(200, '{"id":1,"ownerId":"A","name":"x"}')
    b = _resp(200, '{"id":1,"ownerId":"A","name":"x"}')
    cmp = compare_responses(a, b)
    assert cmp["similarity"] >= 0.95


def test_dynamic_fields_ignored():
    a = _resp(200, '{"id":1,"ownerId":"A","timestamp":"t1","requestId":"r1"}')
    b = _resp(200, '{"id":1,"ownerId":"A","timestamp":"t2","requestId":"r2"}')
    cmp = compare_responses(a, b)
    assert cmp["similarity"] >= 0.9


def test_error_response_low_similarity():
    a = _resp(200, '{"id":1,"ownerId":"A","name":"Project A"}')
    b = _resp(200, '{"error":"Not found"}')
    cmp = compare_responses(a, b)
    assert cmp["similarity"] < 0.6
