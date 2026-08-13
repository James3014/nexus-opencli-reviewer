from reviewer.render import MAX_BODY, render_advisory


def test_render_escapes_markdown_and_html_comment_controls():
    result = render_advisory(
        {"status": "FINDINGS", "summary": "<!-- hide --> **spoof** [x]", "findings": [{"severity": "HIGH", "category": "x|y", "path": "a`b", "reason": "</div>"}]},
        reviewed_head="head",
        attempt_id="a1",
    )
    assert "<!--" not in result and "-->" not in result
    assert "\\*\\*spoof\\*\\*" in result
    assert result.count("NOT APPROVAL") == 2


def test_render_caps_fields_and_body():
    result = render_advisory(
        {"status": "PASS", "summary": "x" * 10000, "findings": [{"severity": "LOW", "category": "c", "path": "p", "reason": "r" * 10000}]},
        reviewed_head="h",
        attempt_id="id",
    )
    assert len(result) <= MAX_BODY
    assert len(result) > 0


def test_render_uses_only_semantic_fields_and_fixed_disclaimer():
    result = render_advisory(
        {"status": "PASS", "summary": "ok", "findings": [], "raw_response": "SECRET", "prompt": "PRIVATE"},
        reviewed_head="h",
        attempt_id="id",
    )
    assert "SECRET" not in result and "PRIVATE" not in result
    assert result.startswith("Automated PRE_REVIEW\nADVISORY ONLY")
    assert result.rstrip().endswith("id:pending")
