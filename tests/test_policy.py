from gateway.policy import Decision, evaluate_tool_call


def test_safe_tool_always_allowed():
    decision, _ = evaluate_tool_call("web_search", {"query": "x"}, injection_flagged=False)
    assert decision == Decision.ALLOW

    decision, _ = evaluate_tool_call("web_search", {"query": "x"}, injection_flagged=True)
    assert decision == Decision.ALLOW


def test_dangerous_tool_requires_confirmation_when_clean():
    decision, _ = evaluate_tool_call("send_email", {"to": "a@b.com"}, injection_flagged=False)
    assert decision == Decision.CONFIRM


def test_dangerous_tool_blocked_after_injection():
    decision, reason = evaluate_tool_call("send_email", {"to": "a@b.com"}, injection_flagged=True)
    assert decision == Decision.BLOCK
    assert "injected" in reason or "flagged" in reason


def test_sensitive_tool_blocked_after_injection():
    decision, _ = evaluate_tool_call("write_file", {"path": "x"}, injection_flagged=True)
    assert decision == Decision.BLOCK


def test_unknown_tool_fails_closed():
    decision, _ = evaluate_tool_call("execute_shell", {"cmd": "rm -rf /"}, injection_flagged=False)
    assert decision == Decision.CONFIRM
