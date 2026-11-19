"""Delegated authority, modelled on OAuth 2.0 Token Exchange (RFC 8693).

The problem (from "Agentic AI Security", Aug 2026): an agent should act on a
short-lived, task-scoped token derived from the *originating human's*
identity, not a shared credential. And when Agent A hands part of a task to
Agent B, authority must not grow at each hop, while every action stays
traceable to the human's original consent.

This module simulates that pattern:

  * exchange_user_token()  – human (subject) -> agent (actor). The token
    carries the consent text, constraints (e.g. max_amount) and a trace id.
  * exchange_for_agent()   – Agent A's token -> Agent B. The child token's
    scopes must be a subset of the parent's; constraints can only tighten;
    expiry can only shorten; chain depth is capped.
  * validate()             – checked on every use, not just at issue: the
    signature, expiry, explicit revocation, the subject still being active,
    and every actor in the chain still being registered, unsuspended and owned
    by an active human. Revoke the human and every live token they
    originated stops working.

Effective authority at any hop = token scopes ∩ that agent's own standing
scopes ∩ the human's current entitlements. It is a delegation *envelope*,
not a grant.

This is a reference simulation with HMAC-signed claims, not an OAuth server.
In production the same claims map to an RFC 8693 `act` claim issued by your
IdP's token-exchange endpoint.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .identity import Directory, now


class DelegationError(PermissionError):
    pass


@dataclass(frozen=True)
class DelegationToken:
    token_id: str
    subject: str                      # originating human
    actor_chain: tuple[str, ...]      # (agent_a, agent_b, ...) — last is current actor
    scopes: frozenset[str]
    consent: str                      # what the human actually asked/consented to
    constraints: tuple[tuple[str, object], ...]
    trace_id: str
    parent_id: str | None
    expires_at: datetime
    sig: str = field(default="", compare=False)

    @property
    def actor(self) -> str:
        return self.actor_chain[-1]

    @property
    def limits(self) -> dict:
        return dict(self.constraints)

    def claims(self) -> dict:
        """RFC 8693-style view: nested `act` claim, outermost = current actor."""
        act: dict | None = None
        for a in self.actor_chain:
            act = {"sub": a, **({"act": act} if act else {})}
        return {
            "jti": self.token_id, "sub": self.subject, "act": act,
            "scope": " ".join(sorted(self.scopes)), "consent": self.consent,
            "constraints": self.limits, "trace_id": self.trace_id,
            "parent_jti": self.parent_id, "exp": self.expires_at.isoformat(),
        }


class TokenService:
    def __init__(self, directory: Directory, key: bytes, audit=None,
                 ttl_minutes: int = 10, max_depth: int = 3) -> None:
        self.dir = directory
        self.key = key
        self.audit = audit
        self.ttl = timedelta(minutes=ttl_minutes)
        self.max_depth = max_depth
        self.revoked: set[str] = set()
        self._parents: dict[str, str | None] = {}

    # ---- helpers --------------------------------------------------------------
    def _sign(self, claims: dict) -> str:
        msg = json.dumps(claims, sort_keys=True, default=str).encode()
        return hmac.new(self.key, msg, hashlib.sha256).hexdigest()

    def _issue(self, **kw) -> DelegationToken:
        tok = DelegationToken(token_id=uuid.uuid4().hex[:12], **kw)
        tok = DelegationToken(**{**tok.__dict__, "sig": self._sign(tok.claims())})
        self._parents[tok.token_id] = tok.parent_id
        if self.audit:
            self.audit.append("token_issued", **tok.claims())
        return tok

    def _check_agent(self, agent_id: str) -> None:
        a = self.dir.agents.get(agent_id)
        if a is None:
            raise DelegationError(f"unregistered agent '{agent_id}'")
        if a.suspended:
            raise DelegationError(f"agent '{agent_id}' is suspended")
        owner = self.dir.humans.get(a.owner_id)
        if owner is None or not owner.active:
            raise DelegationError(f"agent '{agent_id}' has no active owner")

    # ---- exchanges --------------------------------------------------------------
    def exchange_user_token(self, subject_id: str, agent_id: str, scopes: set[str],
                            consent: str, constraints: dict | None = None,
                            trace_id: str | None = None) -> DelegationToken:
        human = self.dir.humans.get(subject_id)
        if human is None or not human.active:
            raise DelegationError(f"subject '{subject_id}' is not an active human")
        self._check_agent(agent_id)
        granted = frozenset(scopes & human.entitlements)
        if not granted:
            raise DelegationError("subject holds none of the requested scopes")
        return self._issue(
            subject=subject_id, actor_chain=(agent_id,), scopes=granted,
            consent=consent, constraints=tuple(sorted((constraints or {}).items())),
            trace_id=trace_id or uuid.uuid4().hex[:16], parent_id=None,
            expires_at=now() + self.ttl,
        )

    def exchange_for_agent(self, parent: DelegationToken, next_agent: str,
                           scopes: set[str],
                           tighten: dict | None = None) -> DelegationToken:
        ok, why = self.validate(parent)
        if not ok:
            raise DelegationError(f"parent token invalid: {why}")
        if len(parent.actor_chain) >= self.max_depth:
            raise DelegationError(f"delegation chain depth {self.max_depth} reached")
        if next_agent in parent.actor_chain:
            raise DelegationError("delegation loop")
        self._check_agent(next_agent)
        expansion = scopes - parent.scopes
        if expansion:
            raise DelegationError(f"scope expansion refused: {sorted(expansion)}")
        limits = parent.limits
        for k, v in (tighten or {}).items():
            # constraints only tighten: numeric -> min; anything else must match
            if k in limits and isinstance(v, (int, float)):
                limits[k] = min(limits[k], v)
            elif k not in limits:
                limits[k] = v
        return self._issue(
            subject=parent.subject, actor_chain=parent.actor_chain + (next_agent,),
            scopes=frozenset(scopes), consent=parent.consent,
            constraints=tuple(sorted(limits.items())), trace_id=parent.trace_id,
            parent_id=parent.token_id,
            expires_at=min(parent.expires_at, now() + self.ttl),
        )

    def revoke(self, token_id: str) -> None:
        self.revoked.add(token_id)

    # ---- validation, on every use ----------------------------------------------
    def validate(self, tok: DelegationToken) -> tuple[bool, str]:
        if not hmac.compare_digest(tok.sig, self._sign(tok.claims())):
            return False, "token signature invalid"
        # revoking any ancestor revokes the whole downstream chain
        tid: str | None = tok.token_id
        while tid:
            if tid in self.revoked:
                return False, "token revoked (or an upstream token in its chain)"
            tid = self._parents.get(tid)
        if now() >= tok.expires_at:
            return False, "token expired"
        subject = self.dir.humans.get(tok.subject)
        if subject is None or not subject.active:
            return False, f"originating human '{tok.subject}' is no longer active"
        for a in tok.actor_chain:
            try:
                self._check_agent(a)
            except DelegationError as e:
                return False, f"delegation chain broken: {e}"
        return True, "ok"
