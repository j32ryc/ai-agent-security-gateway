"""Mock tools for the demo agent. Nothing here touches the real filesystem
outside demo/sandbox/, and send_email never sends anything real -- it just
records what it *would* have sent, so the demo is safe to run unattended and
still lets you prove an attack "succeeded" when the gateway is disabled."""

from __future__ import annotations

import json
from pathlib import Path

from . import fixtures

SANDBOX_DIR = Path(__file__).parent / "sandbox"
SENT_EMAILS: list[dict] = []  # in-memory outbox for the demo


def _ensure_sandbox() -> None:
    SANDBOX_DIR.mkdir(exist_ok=True)
    for name, content in fixtures.SANDBOX_FILES.items():
        path = SANDBOX_DIR / name
        if not path.exists():
            path.write_text(content, encoding="utf-8")


def reset_sandbox() -> None:
    SENT_EMAILS.clear()
    if SANDBOX_DIR.exists():
        for f in SANDBOX_DIR.iterdir():
            f.unlink()
    _ensure_sandbox()


def read_file(path: str) -> str:
    _ensure_sandbox()
    target = (SANDBOX_DIR / path).resolve()
    if SANDBOX_DIR.resolve() not in target.parents and target != SANDBOX_DIR.resolve():
        return "Error: path escapes sandbox"
    if not target.exists():
        return f"Error: {path} not found"
    return target.read_text(encoding="utf-8")


def list_files() -> str:
    _ensure_sandbox()
    return json.dumps([p.name for p in SANDBOX_DIR.iterdir()])


def delete_file(path: str) -> str:
    _ensure_sandbox()
    target = (SANDBOX_DIR / path).resolve()
    if not target.exists():
        return f"Error: {path} not found"
    target.unlink()
    return f"Deleted {path}"


def send_email(to: str, subject: str, body: str) -> str:
    SENT_EMAILS.append({"to": to, "subject": subject, "body": body})
    return f"Email queued to {to} (demo mode: not actually sent)"


def web_search(query: str) -> str:
    results = fixtures.search(query)
    return json.dumps(results, indent=2)


# name -> callable, used by the agent loop to dispatch tool_use blocks
TOOL_IMPLS = {
    "read_file": read_file,
    "list_files": list_files,
    "delete_file": delete_file,
    "send_email": send_email,
    "web_search": web_search,
}

# Tools whose *output* can contain attacker-controlled content and therefore
# must be scanned before being fed back to the model. read_file matters too --
# a file can be poisoned just as easily as a web page.
UNTRUSTED_OUTPUT_TOOLS = {"web_search", "read_file"}

TOOL_SCHEMAS = [
    {
        "name": "web_search",
        "description": (
            "Search the web AND the company's internal knowledge base (support "
            "tickets, help center articles, policy pages) and return short result "
            "snippets. Use this for any lookup you can't answer from the "
            "conversation alone, including support ticket numbers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a text file from the local workspace.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "list_files",
        "description": "List files in the local workspace.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "delete_file",
        "description": "Permanently delete a file from the local workspace.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email on the user's behalf.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
]
