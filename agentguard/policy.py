"""Policy gate: every agent tool call passes through here before it runs.

This is the "separate system to verify agent behaviour" — the agent never
holds credentials itself; it asks the gate, and the gate decides, logs the
decision together with the agent's stated reasoning, and only then executes.

Checks, in order:
  identity      – registered, not suspended, not expired, owner still active
  least agency  – tool is inside the agent's declared purpose
  delegation    – if acting for a human: token valid on use, tool in the
                  delegated scope, delegated constraints (e.g. max_amount) respected
  authority     – owner (and originating human) still hold the scope
  risk-adaptive – human approval only where the *action* is high-impact,
                  irreversible or over a threshold, not on every call
  verification  – actions like commits need an approved independent Verdict
  blast radius  – rate limit
Then: containment. An agent that keeps hitting the boundary is suspended
automatically, without waiting for a human.

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
    scope: str                         # scope required to call it
    sensitive: bool = False            # always needs a live JIT grant
    irreversible: bool = False         # always needs a live JIT grant
    # Risk-adaptive autonomy: return a reason string when *these args* need a
    # human (e.g. amount over a threshold), else None -> agent proceeds alone.
    approval_rule: Callable[[dict], str | None] | None = None
    max_per_minute: int = 30           # crude blast-radius / runaway-loop limit
    requires_verification: bool = False  # e.g. commits: need an approved Verdict


@dataclass
class GateResult:
    decision: Decision
    reason: str
    output: object = None


def amount_over(limit: float, field: str = "amount") -> Callable[[dict], str | None]:
    """Approval rule: autonomous up to `limit`, human approval above it."""
    def rule(args: dict) -> str | None:
        amt = args.get(field, 0)
        return f"{field} {amt} above autonomous limit {limit}" if amt > limit else None
    return rule


class PolicyGate:
    def __init__(self, directory: Directory, audit: AuditLog, tokens=None,
                 contain_after: int = 3, contain_window_min: int = 10) -> None:
        self.dir = directory
        self.audit = audit
        self.tokens = tokens                     # TokenService, optional
        self.contain_after = contain_after
        self.contain_window = timedelta(minutes=contain_window_min)
        self.tools: dict[str, tuple[ToolSpec, Callable[..., object]]] = {}
        self._calls: dict[str, deque] = defaultdict(deque)
        self._denies: dict[str, deque] = defaultdict(deque)

    def register_tool(self, spec: ToolSpec, fn: Callable[..., object]) -> None:
        self.tools[spec.name] = (spec, fn)

    # ---- the decision logic -------------------------------------------------
    def _decide(self, agent_id: str, tool: str, args: dict, token, verdict) -> tuple[Decision, str]:
        agent = self.dir.agents.get(agent_id)
        if agent is None:
            return Decision.DENY, "unknown agent identity"
        if agent.suspended:
            return Decision.DENY, "agent suspended (contained)"
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

        # Least agency: purpose-bound agents only touch the tools their purpose needs.
        if agent.allowed_tools and tool not in agent.allowed_tools:
            return Decision.DENY, f"'{tool}' is outside this agent's purpose (least agency)"

        # Agent authority can't exceed owner's *current* authority either.
        if spec.scope not in owner.entitlements:
            return Decision.DENY, f"owner does not hold scope '{spec.scope}' (can't delegate it)"

        jit = agent.active_jit_scopes()
        if token is not None:
            if self.tokens is None:
                return Decision.DENY, "delegation token presented but no token service configured"
            ok, why = self.tokens.validate(token)
            if not ok:
                return Decision.DENY, why
            if token.actor != agent_id:
                return Decision.DENY, f"token was issued to '{token.actor}', not '{agent_id}'"
            if spec.scope not in token.scopes:
                return Decision.DENY, f"scope '{spec.scope}' not in the human's delegated consent"
            if spec.scope not in self.dir.humans[token.subject].entitlements:
                return Decision.DENY, f"originating human no longer holds '{spec.scope}'"
            max_amt = token.limits.get("max_amount")
            if max_amt is not None and args.get("amount", 0) > max_amt:
                return Decision.DENY, f"amount {args.get('amount')} exceeds delegated limit {max_amt}"

        # Standing authority: the agent's own scopes (a token never adds to these).
        if spec.scope not in agent.scopes and spec.scope not in jit:
            if spec.sensitive:
                # JIT-only scopes are never standing: route to a human, don't hard-deny.
                return Decision.NEEDS_APPROVAL, f"sensitive scope '{spec.scope}' is JIT-only — needs human approval"
            return Decision.DENY, f"scope '{spec.scope}' not granted to agent"

        # Risk-adaptive autonomy: humans only where the action warrants it.
        why_human = None
        if spec.sensitive:
            why_human = f"sensitive scope '{spec.scope}'"
        elif spec.irreversible:
            why_human = f"irreversible action '{tool}'"
        elif spec.approval_rule:
            why_human = spec.approval_rule(args)
        if why_human:
            if spec.scope not in jit:
                return Decision.NEEDS_APPROVAL, f"{why_human} — needs human approval (JIT)"
            approved = f"{why_human}; approved via JIT grant"
        else:
            approved = "within autonomous bounds"

        if spec.requires_verification and (verdict is None or not verdict.approved):
            msg = "change not approved by independent verifier"
            if verdict is not None:
                msg += f": {'; '.join(verdict.findings)}"
            return Decision.DENY, msg

        window = self._calls[agent_id]
        while window and window[0] < now() - timedelta(minutes=1):
            window.popleft()
        if len(window) >= spec.max_per_minute:
            return Decision.DENY, "rate limit exceeded (possible runaway loop)"
        return Decision.ALLOW, approved

    # ---- containment ------------------------------------------------------------
    def _maybe_contain(self, agent_id: str, trace_id: str | None) -> None:
        agent = self.dir.agents.get(agent_id)
        if agent is None or agent.suspended:
            return
        q = self._denies[agent_id]
        q.append(now())
        while q and q[0] < now() - self.contain_window:
            q.popleft()
        if len(q) >= self.contain_after:
            agent.suspended = True
            self.audit.append(
                "containment", agent_id=agent_id, owner_id=agent.owner_id,
                trace_id=trace_id,
                reason=f"{len(q)} denied calls within {self.contain_window} — agent suspended, owner notified",
            )

    # ---- the call path -------------------------------------------------------
    def call(self, agent_id: str, tool: str, args: dict, reasoning: str,
             verdict=None, token=None, trace_id: str | None = None,
             parent_span: str | None = None) -> GateResult:
        decision, reason = self._decide(agent_id, tool, args, token, verdict)
        output = None
        if decision is Decision.ALLOW:
            self._calls[agent_id].append(now())
            _, fn = self.tools[tool]
            try:
                output = fn(**args)
            except Exception as exc:  # tool failure is logged, not hidden
                reason += f"; tool error: {exc}"
        agent = self.dir.agents.get(agent_id)
        trace = trace_id or (token.trace_id if token else None)
        rec = self.audit.append(
            "tool_call",
            trace_id=trace,
            parent_span=parent_span,
            agent_id=agent_id,
            model=getattr(agent, "model", None),
            owner_id=getattr(agent, "owner_id", None),
            subject=token.subject if token else None,          # originating human
            act_chain=list(token.actor_chain) if token else None,
            token_id=token.token_id if token else None,
            consent=token.consent if token else None,
            tool=tool,
            args=args,
            reasoning=reasoning,      # the agent's stated rationale, captured pre-execution
            decision=decision.value,
            reason=reason,
            result=None if output is None else str(output)[:200],
        )
        if decision is Decision.DENY:
            self._maybe_contain(agent_id, trace)
        result = GateResult(decision, reason, output)
        result.span_id = rec["hash"][:16]  # lets a caller chain the next span to this one
        return result
