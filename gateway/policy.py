"""
Tool-call risk policy.

Every tool an agent can invoke is assigned a risk tier. The policy turns
(tool, args, "was injected content involved in this turn?") into one of three
decisions: ALLOW, CONFIRM (require a human in the loop), or BLOCK.

The key rule that isn't obvious from the tier table alone: a DANGEROUS tool call
that follows a flagged injection in the same turn is auto-escalated to BLOCK
rather than CONFIRM. If the model's reasoning was already steered by injected
content, a human clicking "confirm" is reviewing a decision made under the
attacker's influence, not the user's -- so we don't give the attacker a shot at a
social-engineered approval.
"""

from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "safe"
    SENSITIVE = "sensitive"
    DANGEROUS = "dangerous"


class Decision(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


# Default risk classification for the demo agent's toolset. A real deployment
# would load this from config rather than hardcoding it.
TOOL_RISK_MAP: dict[str, RiskLevel] = {
    "web_search": RiskLevel.SAFE,
    "read_file": RiskLevel.SAFE,
    "list_files": RiskLevel.SAFE,
    "send_email": RiskLevel.DANGEROUS,
    "delete_file": RiskLevel.DANGEROUS,
    "execute_shell": RiskLevel.DANGEROUS,
    "write_file": RiskLevel.SENSITIVE,
}

DEFAULT_UNKNOWN_TOOL_RISK = RiskLevel.DANGEROUS  # fail closed on anything not in the map


def get_risk_level(tool_name: str) -> RiskLevel:
    return TOOL_RISK_MAP.get(tool_name, DEFAULT_UNKNOWN_TOOL_RISK)


def evaluate_tool_call(tool_name: str, tool_args: dict, injection_flagged: bool) -> tuple[Decision, str]:
    """Return (decision, human_readable_reason)."""
    risk = get_risk_level(tool_name)

    if risk == RiskLevel.SAFE:
        return Decision.ALLOW, f"{tool_name} is classified SAFE"

    if risk == RiskLevel.SENSITIVE:
        if injection_flagged:
            return Decision.BLOCK, (
                f"{tool_name} is SENSITIVE and this turn contained flagged content; "
                "blocking rather than trusting a confirmation made under injected influence"
            )
        return Decision.CONFIRM, f"{tool_name} is SENSITIVE, requires human confirmation"

    # DANGEROUS
    if injection_flagged:
        return Decision.BLOCK, (
            f"{tool_name} is DANGEROUS and this turn contained flagged content; auto-blocked"
        )
    return Decision.CONFIRM, f"{tool_name} is DANGEROUS, requires explicit human confirmation"
