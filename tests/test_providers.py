"""Provider resolution tests -- pure logic, no API key or network needed."""

import pytest

from gateway import providers


def test_infers_deepseek_from_model_name():
    assert providers.provider_for_model("deepseek-v4-flash") == "deepseek"
    assert providers.provider_for_model("deepseek-v4-pro") == "deepseek"


def test_infers_gemini_from_model_name():
    assert providers.provider_for_model("gemini-2.5-flash") == "gemini"
    assert providers.provider_for_model("gemini-3.5-flash-lite") == "gemini"


def test_inference_is_case_insensitive():
    assert providers.provider_for_model("Gemini-2.5-Flash") == "gemini"


def test_unknown_model_falls_back_to_default():
    # An unrecognized name shouldn't crash -- it keeps the historical default
    # so existing setups behave exactly as before this module existed.
    assert providers.provider_for_model("some-proxy-model") == providers.DEFAULT_PROVIDER


def test_explicit_override_wins_over_inference():
    assert providers.provider_for_model("deepseek-v4-flash", override="gemini") == "gemini"


def test_unknown_override_raises():
    with pytest.raises(providers.ProviderError):
        providers.provider_for_model("deepseek-v4-flash", override="openai")


def test_deepseek_gets_thinking_disabled_not_reasoning_effort():
    kwargs = providers.completion_kwargs("deepseek-v4-flash")
    assert kwargs["extra_body"] == {"thinking": {"type": "disabled"}}
    # reasoning_effort is Gemini's spelling and DeepSeek rejects unknown fields.
    assert "reasoning_effort" not in kwargs


def test_gemini_gets_reasoning_effort_not_thinking_extra_body():
    kwargs = providers.completion_kwargs("gemini-3.5-flash")
    # "minimal" is the measured best default: it is accepted by more Gemini
    # models than "none" and costs ~10x fewer tokens than "low", which still
    # runs a round of hidden reasoning. See PROVIDERS for the per-model table.
    assert kwargs["reasoning_effort"] == "minimal"
    # DeepSeek's extra_body must never be sent to Gemini.
    assert "extra_body" not in kwargs


def test_completion_kwargs_are_not_shared_between_calls():
    # Guard against a caller mutating the module-level PROVIDERS spec.
    a = providers.completion_kwargs("deepseek-v4-flash")
    a["extra_body"]["thinking"]["type"] = "enabled"
    b = providers.completion_kwargs("deepseek-v4-flash")
    assert b["extra_body"] == {"thinking": {"type": "disabled"}}


def test_missing_api_key_raises_actionable_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(providers.ProviderError) as exc:
        providers.make_client("gemini-2.5-flash")
    # The message should name both the model and the env var to set.
    assert "GEMINI_API_KEY" in str(exc.value)
