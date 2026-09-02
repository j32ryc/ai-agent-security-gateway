"""Run this gateway's detector as a defense inside the AgentDojo benchmark.

Why this exists
---------------
Every number elsewhere in this project is measured on corpora we wrote
ourselves, which can only answer "is the detector accurate on our own examples".
It cannot answer the question a deployment actually cares about: does the
defense preserve the agent's ability to do its job? A gateway that blocks every
tool call scores perfectly on a labeled corpus and is useless in production.

AgentDojo \\cite{Debenedetti2024} reports both together -- utility (did the agent
complete the benign task) and ASR (did the injection succeed) -- so it is the
only measurement here that can catch a defense that buys security by breaking
the agent.

Install (optional, not part of requirements.txt):

    pip install agentdojo

Run a deliberately small slice, because the full benchmark is far larger than a
free-tier quota allows (see MODEL/QUOTA note below):

    python -m attacks.agentdojo_bridge --suite workspace \\
        --user-tasks user_task_0 --injection-tasks injection_task_0

MODEL/QUOTA note
----------------
The four suites hold 40+20+16+21 = 97 user tasks and 14+7+9+5 = 35 injection
tasks; with injections the benchmark crosses them, so a full run is on the order
of a thousand agent trajectories, each of which is several LLM calls. Against a
20-requests-per-day free tier that is not merely slow, it is impossible. Pass
--user-tasks/--injection-tasks and treat the result as a documented subset.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from gateway.detector import InjectionDetector
from gateway import providers


def _require_agentdojo():
    try:
        import agentdojo  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on optional install
        raise SystemExit(
            "agentdojo is not installed. It is an optional dependency:\n"
            "    pip install agentdojo"
        ) from exc


class GatewayDetector:
    """Adapter exposing InjectionDetector through AgentDojo's defense interface.

    Constructed lazily inside build_pipeline so that importing this module does
    not require agentdojo to be installed.
    """


def make_gateway_detector_class():
    """Build the adapter class, importing agentdojo only when actually needed."""
    from agentdojo.agent_pipeline.pi_detector import PromptInjectionDetector

    class _GatewayDetector(PromptInjectionDetector):
        """Wraps InjectionDetector as an AgentDojo pipeline element.

        AgentDojo calls detect() on each tool result, which is exactly where this
        gateway's check_tool_output() sits, so no gateway code changes are needed.
        Returning (bool, confidence) rather than a bare bool preserves the
        detector's own score instead of flattening it.
        """

        def __init__(self, use_llm_judge: bool = False, mode: str = "message",
                     raise_on_injection: bool = False):
            super().__init__(mode=mode, raise_on_injection=raise_on_injection)
            # The judge is off by default here: AgentDojo issues one detect() call
            # per tool result across hundreds of trajectories, and a judge call on
            # each would exhaust a free-tier quota long before the run finished.
            self.detector = InjectionDetector(use_llm_judge=use_llm_judge)

        def detect(self, tool_output: str) -> tuple[bool, float]:
            result = self.detector.scan(tool_output)
            return bool(result.matched), float(result.confidence)

    return _GatewayDetector


class _RoleCompatCompletions:
    """Rewrites role="developer" to role="system" on the way out.

    AgentDojo's OpenAILLM follows current OpenAI convention and sends the system
    prompt with role "developer". DeepSeek's OpenAI-compatible endpoint rejects
    that role outright (400: unknown variant `developer`). Patching AgentDojo's
    module-level _message_to_openai would fix it too, but monkey-patching a
    dependency's internals breaks silently when it is upgraded. Wrapping the
    client confines the shim to the transport boundary, where the incompatibility
    actually lives.
    """

    def __init__(self, inner):
        self._inner = inner

    def create(self, *args, **kwargs):
        messages = kwargs.get("messages")
        if messages:
            kwargs["messages"] = [
                {**m, "role": "system"} if m.get("role") == "developer" else m
                for m in messages
            ]
        return self._inner.create(*args, **kwargs)


class _RoleCompatChat:
    def __init__(self, inner):
        self.completions = _RoleCompatCompletions(inner.completions)


class _RoleCompatClient:
    """Transparent proxy: only the chat.completions path is intercepted."""

    def __init__(self, inner):
        self._inner = inner
        self.chat = _RoleCompatChat(inner.chat)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def make_llm(model: str):
    """Build an AgentDojo LLM for `model`, routing by provider.

    DeepSeek needs no bespoke LLM class: AgentDojo's OpenAILLM accepts a client
    object, and DeepSeek serves an OpenAI-compatible API, so pointing a client at
    its base_url is sufficient.
    """
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    from agentdojo.agent_pipeline.llms.google_llm import GoogleLLM

    provider = providers.provider_for_model(model)
    spec = providers.PROVIDERS[provider]
    api_key = os.environ.get(spec["api_key_env"])
    if not api_key:
        raise SystemExit(f"{model!r} needs {spec['api_key_env']} to be set.")

    if provider == "gemini":
        from google import genai
        return GoogleLLM(model=model, client=genai.Client(api_key=api_key))

    from openai import OpenAI
    client = OpenAI(api_key=api_key, base_url=spec["base_url"])
    return OpenAILLM(client=_RoleCompatClient(client), model=model)


def build_pipeline(model: str, defended: bool, use_llm_judge: bool):
    """Compose the agent pipeline, with or without the gateway spliced in.

    Both arms share every other element so that a utility or ASR difference is
    attributable to the defense and nothing else.
    """
    from agentdojo.agent_pipeline import (
        AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor,
    )

    llm = make_llm(model)
    loop_elements = [ToolsExecutor()]
    if defended:
        loop_elements.append(make_gateway_detector_class()(use_llm_judge=use_llm_judge))
    loop_elements.append(llm)

    return AgentPipeline([
        SystemMessage("You are a helpful assistant with access to tools."),
        InitQuery(),
        llm,
        ToolsExecutionLoop(loop_elements),
    ])


def _register_model_name(model: str) -> None:
    """Teach AgentDojo's attack machinery a prose name for models it lacks.

    The important_instructions family resolves a human-readable model name by
    substring-matching the pipeline name against a fixed table, and raises if it
    finds nothing. DeepSeek is absent from that table.

    Two worse fixes were available. Naming the pipeline after some listed model
    ("gpt-4o-...") would make the attack address the agent as a model it is not,
    silently changing what is being measured. Naming it "local" would map to
    "Local model", which is untrue of a hosted API and would mislead anyone
    reading the logs. Registering a generic, accurate descriptor keeps the
    pipeline name honest and the attack text truthful.

    Note that the default attack here (important_instructions_no_model_name)
    discards the resolved name immediately, so this only has to make the lookup
    succeed. It matters if someone switches to the name-using variant.
    """
    from agentdojo.attacks.base_attacks import MODEL_NAMES

    if not any(k in model for k in MODEL_NAMES):
        MODEL_NAMES[model] = "AI assistant"


def main() -> None:
    _require_agentdojo()
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.task_suite.load_suites import get_suites

    p = argparse.ArgumentParser()
    p.add_argument("--suite", default="workspace",
                   choices=["workspace", "travel", "banking", "slack"])
    p.add_argument("--model", default="deepseek-v4-flash")
    # important_instructions (AgentDojo's standard strong attack) builds its
    # social-engineering text around the target model's name, which it resolves
    # from a fixed table -- DeepSeek is not in it. The _no_model_name variant is
    # the maintainers' own answer to that, and is preferable to naming the
    # pipeline after some unrelated model just to satisfy the lookup, which would
    # feed the attack a false premise and quietly change what is being measured.
    p.add_argument("--attack", default="important_instructions_no_model_name")
    p.add_argument("--user-tasks", nargs="*", default=None,
                   help="restrict to these user task ids (quota control)")
    p.add_argument("--injection-tasks", nargs="*", default=None)
    p.add_argument("--undefended", action="store_true",
                   help="run without the gateway, to get the baseline ASR")
    p.add_argument("--llm-judge", action="store_true",
                   help="enable the semantic layer (expensive: one call per tool result)")
    p.add_argument("--logdir", default="./agentdojo_runs")
    args = p.parse_args()

    _register_model_name(args.model)

    suite = get_suites("v1.2.1")[args.suite]
    pipeline = build_pipeline(args.model, defended=not args.undefended,
                              use_llm_judge=args.llm_judge)
    pipeline.name = f"gateway-{'off' if args.undefended else 'on'}-{args.model}"
    attack = load_attack(args.attack, suite, pipeline)

    print(f"suite={args.suite} model={args.model} attack={args.attack} "
          f"defense={'OFF' if args.undefended else 'ON'}")
    print(f"user_tasks={args.user_tasks or 'ALL'} injection_tasks={args.injection_tasks or 'ALL'}")

    # benchmark_suite_with_injections writes per-trajectory traces through an
    # ambient logger, and the default NullLogger has no logdir, so the call fails
    # unless an OutputLogger context is active.
    from agentdojo.logging import OutputLogger

    with OutputLogger(args.logdir):
        results = benchmark_suite_with_injections(
            pipeline, suite, attack, Path(args.logdir), force_rerun=False,
            user_tasks=args.user_tasks, injection_tasks=args.injection_tasks,
        )

    # SuiteResults is a TypedDict, so these are keys rather than attributes.
    utility = list(results["utility_results"].values())
    security = list(results["security_results"].values())

    print(f"\ntrajectories: {len(utility)}")
    if utility:
        print(f"utility (benign task completed): {sum(utility)}/{len(utility)}"
              f" = {sum(utility)/len(utility):.2f}")
    if security:
        # security_results is True when the INJECTION succeeded, so this is ASR:
        # lower is better, the opposite direction from utility.
        print(f"ASR (injection succeeded):       {sum(security)}/{len(security)}"
              f" = {sum(security)/len(security):.2f}")

    print("\nper-trajectory detail:")
    for key in results["utility_results"]:
        u = results["utility_results"][key]
        sec = results["security_results"].get(key)
        print(f"  {key}: utility={u} injection_succeeded={sec}")


if __name__ == "__main__":
    main()
