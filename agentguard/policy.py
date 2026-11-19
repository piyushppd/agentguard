"""Policy gate: every agent tool call passes through here before it runs.

This is the "separate system to verify agent behaviour" — the agent never
holds credentials itself; it asks the gate, and the gate decides, logs the
decision together with the agent's stated reasoning, and only then executes.

Decisions: ALLOW, DENY, or NEEDS_APPROVAL (route to a human for JIT).
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import Callable

from .audit import AuditLog
from .identity import Directory, now


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


@dataclass
class ToolSpec:
    name: str
    scope: str                 # scope required to call it
    sensitive: bool = False    # sensitive tools always need a live JIT grant
    max_per_minute: int = 30   # crude blast-radius / runaway-loop limit
    requires_verification: bool = False  # e.g. commits: need an approved Verdict


@dataclass
class GateResult:
    decision: Decision
    reason: str
    output: object = None


class PolicyGate:
    def __init__(self, directory: Directory, audit: AuditLog) -> None:
        self.dir = directory
        self.audit = audit
        self.tools: dict[str, tuple[ToolSpec, Callable[..., object]]] = {}
        self._calls: dict[str, deque] = defaultdict(deque)

    def register_tool(self, spec: ToolSpec, fn: Callable[..., object]) -> None:
        self.tools[spec.name] = (spec, fn)

    # ---- the decision logic -------------------------------------------------
    def _decide(self, agent_id: str, tool: str) -> tuple[Decision, str]:
        agent = self.dir.agents.get(agent_id)
        if agent is None:
            return Decision.DENY, "unknown agent identity"
        if agent.suspended:
            return Decision.DENY, "agent suspended"
        if now() >= agent.expires_at:
            return Decision.DENY, "agent identity expired"

        owner = self.dir.humans.get(agent.owner_id)
        # Delegated-authority check: revoking the human must revoke the agent,
        # even if nobody remembered to deprovision the agent's credentials.
        if owner is None or not owner.active:
            return Decision.DENY, f"delegating owner '{agent.owner_id}' is no longer active"

        if tool not in self.tools:
            return Decision.DENY, f"tool '{tool}' not registered"
        spec, _ = self.tools[tool]

        # Agent authority can't exceed owner's *current* authority either.
        if spec.scope not in owner.entitlements:
            return Decision.DENY, f"owner does not hold scope '{spec.scope}' (can't delegate it)"

        jit = agent.active_jit_scopes()
        if spec.sensitive:
            if spec.scope in jit:
                return Decision.ALLOW, "sensitive tool, valid JIT grant"
            return Decision.NEEDS_APPROVAL, f"sensitive scope '{spec.scope}' needs a JIT grant"

        if spec.scope not in agent.scopes and spec.scope not in jit:
            return Decision.DENY, f"scope '{spec.scope}' not granted to agent"

        window = self._calls[agent_id]
        cutoff = now() - timedelta(minutes=1)
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= spec.max_per_minute:
            return Decision.DENY, "rate limit exceeded (possible runaway loop)"
        return Decision.ALLOW, "within standing scopes"

    # ---- the call path -------------------------------------------------------
    def call(self, agent_id: str, tool: str, args: dict, reasoning: str,
             verdict=None) -> GateResult:
        decision, reason = self._decide(agent_id, tool)
        spec = self.tools.get(tool, (None, None))[0]
        if decision is Decision.ALLOW and spec and spec.requires_verification:
            if verdict is None or not verdict.approved:
                decision = Decision.DENY
                reason = "change not approved by independent verifier"
                if verdict is not None:
                    reason += f": {'; '.join(verdict.findings)}"
        output = None
        if decision is Decision.ALLOW:
            self._calls[agent_id].append(now())
            _, fn = self.tools[tool]
            try:
                output = fn(**args)
            except Exception as exc:  # tool failure is logged, not hidden
                reason += f"; tool error: {exc}"
        agent = self.dir.agents.get(agent_id)
        self.audit.append(
            "tool_call",
            agent_id=agent_id,
            model=getattr(agent, "model", None),
            owner_id=getattr(agent, "owner_id", None),
            tool=tool,
            args=args,
            reasoning=reasoning,      # the agent's stated rationale, captured pre-execution
            decision=decision.value,
            reason=reason,
        )
        return GateResult(decision, reason, output)
