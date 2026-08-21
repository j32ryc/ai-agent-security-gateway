# AI Agent Security Gateway

A middleware layer for tool-using LLM agents that detects prompt injection and
enforces a risk-tiered policy on tool calls, with a full audit trail — applying
security-monitoring practice (detect → triage → enforce → log) to a class of
attack that's specific to agentic AI.

Built as a hands-on bridge between application security and AI agent
engineering: the trust-boundary problem here is the same one SQL injection and
XSS taught the industry — an agent that treats retrieved content as trustworthy
instructions has the same bug as a query that treats user input as trustworthy
code.

## The problem

A tool-using agent (file access, email, web search, shell, ...) has two
distinct trust boundaries that are easy to blur:

| Attack | What happens |
|---|---|
| **Direct prompt injection** | The user's own message tries to override the agent's system prompt or rules. |
| **Indirect prompt injection** | Content the agent *retrieves* (a web page, a file, a ticket, search results) contains hidden instructions that the model then obeys as if the user had typed them. This is the higher-severity case — the "user" here can be anyone who can get content in front of the agent. |
| **Excessive agency** | The agent calls a high-impact tool (send email, delete a file, run a shell command) without anyone actually authorizing that specific action. |
| **Data exfiltration** | Once an agent is manipulated, it has legitimate credentials to read sensitive data and legitimate tools to send it somewhere — injection + agency combine into a full attack chain. |

The included demo agent ships with a working example of the second row: a
`web_search` result that looks like an ordinary support ticket but contains a
hidden instruction telling the agent to read `secrets.txt` and email it to an
external address. Run it unprotected and the agent falls for it.

## Architecture

```mermaid
flowchart TD
    U[User message] --> IN[Gateway: check_input]
    IN -->|clean| AGENT[Agent / LLM]
    IN -->|flagged| LOG1[(Audit log)]
    AGENT -->|wants to call a tool| AUTH[Gateway: authorize_tool_call]
    AUTH -->|SAFE| EXEC[Execute tool]
    AUTH -->|SENSITIVE / DANGEROUS, clean turn| CONFIRM{Human confirmation}
    AUTH -->|SENSITIVE / DANGEROUS, injection flagged this turn| BLOCK[Blocked automatically]
    CONFIRM -->|approved| EXEC
    CONFIRM -->|denied| BLOCK
    EXEC --> OUT[Gateway: check_tool_output]
    OUT -->|clean| BACK[Fed back to agent as-is]
    OUT -->|flagged| SANITIZE[Wrapped with a security notice, fed back as data]
    BLOCK --> LOG2[(Audit log)]
    SANITIZE --> LOG2
    BACK --> AGENT
```

### Defense in depth, not one filter

The gateway doesn't rely on catching the injection once. Two independent
layers both have to fail for an attack to succeed end to end:

1. **Content scanning** (`gateway/detector.py`) — every user input and every
   tool output is scanned before it reaches the model. A cheap heuristic
   pattern layer runs first (free, no API call); only inconclusive cases
   escalate to an LLM-as-judge classifier. The judge is given the suspect text
   as `<content>` to *classify*, never as instructions to follow — a
   classifier prompt that concatenates untrusted text into its instruction
   channel is itself injectable, which defeats the purpose.
2. **Tool-call policy** (`gateway/policy.py`) — independent of whether the
   scanner caught anything, every tool call is checked against a risk tier
   (`SAFE` / `SENSITIVE` / `DANGEROUS`). If *this turn* already had a flagged
   input or tool output, a `DANGEROUS` call is auto-**blocked** rather than
   routed to human confirmation — because a human clicking "approve" at that
   point would be approving a decision the model already made under the
   attacker's influence, not the user's. [`tests/test_policy.py`](tests/test_policy.py)
   covers this rule directly, including the case where the confirmation
   callback would have said yes.

Every scan and every decision — allow, confirm, block — is written to a
SQLite audit log (`gateway/audit_log.py`), so a session can be replayed after
the fact rather than only alerted on in real time.

## Quickstart

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # required for the demo agent and the LLM-judge layer
```

**CLI demo** — runs the poisoned-ticket scenario once unprotected, once
protected, so you can see the gateway make the difference:

```bash
python -m demo.run_cli --scenario indirect_injection --unprotected
python -m demo.run_cli --scenario indirect_injection --protected
```

Or chat freely:

```bash
python -m demo.run_cli
```

**Dashboard** — chat on the left, live security log on the right, toggle the
gateway on/off from the sidebar:

```bash
streamlit run app.py
```

**Tests and evaluation** (no API key needed — these exercise the heuristic
layer only):

```bash
pytest tests/ -v
python -m attacks.run_eval              # heuristic layer only
python -m attacks.run_eval --llm-judge  # full two-layer detector, costs a few cents
```

## Evaluation

[`attacks/payloads.py`](attacks/payloads.py) is a small labeled corpus (15
attack prompts across 4 categories, 12 benign prompts — including benign
sentences that intentionally reuse trigger words like "system prompt" or "act
as", to test for false positives). Measured heuristic-only results:

```
Cases: 27 (15 attacks, 12 benign)
TP=15 FP=1 TN=11 FN=0
Precision=0.94  Recall=1.00  F1=0.97
```

The one false positive — *"Can you act as a rubber duck and let me explain my
code to you?"* — is flagged by the `role_hijack` pattern (`act as ...`) purely
on phrasing. That's the heuristic layer's known failure mode: it matches
shape, not intent, so it will always have some false-positive surface. It's
exactly the case the LLM-judge layer exists to resolve — run
`python -m attacks.run_eval --llm-judge` with an API key to see the two-layer
number.

## Known limitations

- **Heuristics are a keyword/shape arms race.** A determined attacker can
  paraphrase around any fixed pattern list. That's *why* there's a second,
  semantic layer — but the judge model itself is also attackable in
  principle (e.g. an extremely long payload designed to exhaust its context).
  This is a demo-scale mitigation, not a claim of complete coverage.
- **Tool risk tiers are hardcoded** in `gateway/policy.py` for the demo
  toolset. A real deployment would load this from config and probably scope
  it per-user or per-session rather than globally.
- **No real destructive actions.** `send_email` is mocked and file tools are
  sandboxed to `demo/sandbox/` on purpose, so the "unprotected" scenario is
  safe to actually run and watch fail.
- **This is not a substitute for least-privilege tool design.** The gateway
  reduces the blast radius of a successful injection; it doesn't replace
  scoping what tools an agent has access to in the first place.

## Project structure

```
gateway/            # the reusable security layer
  detector.py        heuristic + LLM-judge prompt injection scanner
  policy.py           risk-tiered tool-call authorization (ALLOW/CONFIRM/BLOCK)
  audit_log.py         SQLite-backed event log
  gateway.py          ties the above together into one object

demo/                # a small tool-using agent to exercise the gateway against
  tools.py             mock file/email/search tools (sandboxed, safe to run)
  fixtures.py          canned data, including one indirect-injection payload
  agent.py             Claude tool-use loop, protected/unprotected modes
  run_cli.py           interactive CLI + scripted attack scenario

attacks/             # labeled test corpus + precision/recall eval
tests/               # pytest unit tests for the detector and policy (no API key needed)
app.py               # Streamlit dashboard
```

## Tech stack

Python, [Anthropic API](https://docs.anthropic.com/) (Claude, tool use),
Streamlit, SQLite, pytest.
