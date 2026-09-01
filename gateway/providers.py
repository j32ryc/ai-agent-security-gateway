"""Provider resolution shared by the demo agent and the detector's LLM judge.

Both talk to OpenAI-compatible endpoints, so the only things that vary across
providers are the base URL, which env var holds the key, and how each one wants
to be told not to spend its budget on hidden reasoning tokens.

Provider is inferred from the model name, so switching providers is a one-var
change:

    DEMO_AGENT_MODEL=gemini-2.5-flash python -m demo.run_cli --scenario indirect_injection

Set DEMO_AGENT_PROVIDER / GATEWAY_JUDGE_PROVIDER only to override that inference
(e.g. when pointing at a proxy that serves a model under a non-standard name).
"""

from __future__ import annotations

import copy
import os

# Thinking/reasoning is disabled or minimized on both providers for the same
# reason: the judge does short JSON classification and the agent does structured
# tool_calls, and on both providers extended reasoning has been observed to
# consume the whole token budget before producing any parseable output.
PROVIDERS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "api_key_env": "DEEPSEEK_API_KEY",
        # DeepSeek accepts an explicit off switch.
        "extra_body": {"thinking": {"type": "disabled"}},
        "params": {},
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "api_key_env": "GEMINI_API_KEY",
        # Gemini exposes this as reasoning_effort on the OpenAI-compat layer.
        # Measured against the flash models this project uses:
        #
        #   model                    minimal   none
        #   gemini-3.5-flash         ok        ok
        #   gemini-3.6-flash         ok        400 BadRequest
        #   gemini-3.7-flash         400       500 InternalServerError
        #   gemini-3-flash-preview   ok        ok
        #   gemini-3.1-flash-lite    ok        ok
        #
        # So no single value is universal; "minimal" covers the most models and
        # costs ~7 total tokens on a trivial call versus ~67 for "low", because
        # "low" still runs (and bills for) a round of hidden reasoning. Override
        # with GEMINI_REASONING_EFFORT for a model that rejects it.
        #
        # Separately: the empty-response failure mode is NOT caused by this
        # setting. It happens when max_tokens is small enough that hidden
        # reasoning tokens consume the whole budget before any content is
        # emitted -- max_tokens=20 with "low" returns content=None and
        # completion_tokens=0. Callers must leave enough headroom.
        "extra_body": {},
        "params": {"reasoning_effort": os.environ.get("GEMINI_REASONING_EFFORT", "minimal")},
    },
}

DEFAULT_PROVIDER = "deepseek"


class ProviderError(RuntimeError):
    """Raised for an unknown provider or a missing API key."""


def provider_for_model(model: str, override: str | None = None) -> str:
    """Infer the provider from a model name, or honor an explicit override."""
    if override:
        key = override.strip().lower()
        if key not in PROVIDERS:
            raise ProviderError(
                f"Unknown provider {override!r}. Known: {', '.join(sorted(PROVIDERS))}"
            )
        return key

    name = (model or "").strip().lower()
    for key in PROVIDERS:
        if name.startswith(key):
            return key
    return DEFAULT_PROVIDER


def make_client(model: str, override: str | None = None):
    """Build an OpenAI-compatible client pointed at the right provider."""
    from openai import OpenAI  # local import: optional when the judge is disabled

    provider = provider_for_model(model, override)
    spec = PROVIDERS[provider]
    api_key = os.environ.get(spec["api_key_env"])
    if not api_key:
        raise ProviderError(
            f"Model {model!r} resolves to provider {provider!r}, which needs "
            f"{spec['api_key_env']} to be set."
        )
    return OpenAI(api_key=api_key, base_url=spec["base_url"])


def completion_kwargs(model: str, override: str | None = None) -> dict:
    """Per-provider kwargs to splat into chat.completions.create().

    Returns only the keys that provider actually needs, so we never send
    DeepSeek's extra_body to Gemini (which rejects unknown fields) or vice versa.

    Deep-copied so a caller that mutates the result can't corrupt PROVIDERS for
    every later call.
    """
    spec = PROVIDERS[provider_for_model(model, override)]
    kwargs: dict = copy.deepcopy(spec["params"])
    if spec["extra_body"]:
        kwargs["extra_body"] = copy.deepcopy(spec["extra_body"])
    return kwargs
