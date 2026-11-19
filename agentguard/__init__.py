"""AgentGuard — treat AI agents as insider risk.

A small, dependency-free reference implementation of:
  identity      – agents as non-human identities with accountable human owners
  delegation    – RFC 8693-style token exchange and agent-to-agent chains
  policy        – a gate every tool call passes through (least agency,
                  risk-adaptive approval, JIT, SoD, containment)
  audit         – hash-chained, tamper-evident log of actions and agent reasoning
  siem          – SIEM-ready export of the trail
  verifier      – independent checks on agent-produced changes
  certification – evidence-based access review, scheduled or event-triggered
"""
from .audit import AuditLog
from .certification import run_campaign, to_markdown, unregistered_identities
from .delegation import DelegationError, DelegationToken, TokenService
from .identity import Agent, Directory, Human
from .policy import Decision, PolicyGate, ToolSpec, amount_over
from .siem import export_jsonl
from .verifier import Change, verify

__version__ = "0.2.0"

__all__ = [
    "Agent", "AuditLog", "Change", "Decision", "DelegationError", "DelegationToken",
    "Directory", "Human", "PolicyGate", "TokenService", "ToolSpec", "amount_over",
    "export_jsonl", "run_campaign", "to_markdown", "unregistered_identities", "verify",
]
