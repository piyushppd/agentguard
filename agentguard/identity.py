"""Identity model for humans and AI agents.

Core idea (Nadella: "treat agents as insider risk"): every agent is a
first-class, non-human identity with
  * an accountable human owner who delegated authority to it,
  * a small set of standing scopes (least privilege),
  * time-boxed just-in-time (JIT) grants for anything sensitive,
  * an expiry date, so no agent lives forever by default.

An agent's authority can never exceed, or outlive, the human who delegated it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


def now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Human:
    user_id: str
    name: str
    department: str
    entitlements: set[str] = field(default_factory=set)
    active: bool = True  # False = leaver / suspended


@dataclass
class JITGrant:
    scope: str
    approved_by: str
    reason: str
    expires_at: datetime

    def valid(self, at: datetime | None = None) -> bool:
        return (at or now()) < self.expires_at


@dataclass
class Agent:
    agent_id: str
    purpose: str
    owner_id: str                      # accountable human delegator
    model: str                         # e.g. "claude-sonnet", "llama-3-70b"
    scopes: set[str] = field(default_factory=set)
    expires_at: datetime = field(default_factory=lambda: now() + timedelta(days=90))
    jit_grants: list[JITGrant] = field(default_factory=list)
    suspended: bool = False
    # Least agency: the tools this agent's purpose needs. Empty = not purpose-bound.
    allowed_tools: set[str] = field(default_factory=set)

    def active_jit_scopes(self, at: datetime | None = None) -> set[str]:
        return {g.scope for g in self.jit_grants if g.valid(at)}


class Directory:
    """A tiny identity store: the system of record for humans and agents."""

    def __init__(self) -> None:
        self.humans: dict[str, Human] = {}
        self.agents: dict[str, Agent] = {}

    def add_human(self, h: Human) -> Human:
        self.humans[h.user_id] = h
        return h

    def register_agent(self, a: Agent) -> Agent:
        owner = self.humans.get(a.owner_id)
        if owner is None or not owner.active:
            raise ValueError(f"Agent {a.agent_id} needs an active human owner")
        # Delegation rule: an agent cannot be given scopes its owner lacks.
        excess = a.scopes - owner.entitlements
        if excess:
            raise ValueError(
                f"Owner {owner.user_id} cannot delegate scopes they do not hold: {sorted(excess)}"
            )
        self.agents[a.agent_id] = a
        return a

    def grant_jit(self, agent_id: str, scope: str, approver_id: str,
                  reason: str, minutes: int = 30) -> JITGrant:
        agent = self.agents[agent_id]
        approver = self.humans.get(approver_id)
        if approver is None or not approver.active:
            raise PermissionError("JIT approver must be an active human")
        if approver_id == agent.owner_id:
            # Separation of duties: the owner can't self-approve elevation.
            raise PermissionError("Owner cannot approve their own agent's elevation")
        grant = JITGrant(scope, approver_id, reason, now() + timedelta(minutes=minutes))
        agent.jit_grants.append(grant)
        return grant

    def offboard_human(self, user_id: str) -> list[str]:
        """Leaver event. Note: we deliberately do NOT touch the agents here,
        because most real IAM stacks don't — the policy gate and the
        certification campaign have to catch the orphaned agents.
        Returns the agents this human owns, so a review can be *triggered*
        by the event instead of waiting for the next quarterly cycle."""
        self.humans[user_id].active = False
        return [a.agent_id for a in self.agents.values() if a.owner_id == user_id]
