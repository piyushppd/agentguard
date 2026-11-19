"""AgentGuard — treat AI agents as insider risk.

A small, dependency-free reference implementation of:
  identity      – agents as non-human identities with accountable human owners
  policy        – a gate every tool call passes through (least privilege, JIT, SoD)
  audit         – hash-chained, tamper-evident log of actions and agent reasoning
  verifier      – independent checks on agent-produced changes
  certification – an access review campaign built for agent populations
"""
from .audit import AuditLog
from .certification import run_campaign, to_markdown
from .identity import Agent, Directory, Human
from .policy import Decision, PolicyGate, ToolSpec
from .verifier import Change, verify

__all__ = [
    "Agent", "AuditLog", "Change", "Decision", "Directory", "Human",
    "PolicyGate", "ToolSpec", "run_campaign", "to_markdown", "verify",
]
