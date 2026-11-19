"""Independent verifier for agent-produced changes.

Nadella: generating code is cheap, verifying it is hard; a model may "make
tests pass by deleting the failing ones", and a critic from the same model
family can share the same blind spots.

So the verifier has two layers:
  1. Deterministic checks that no model can talk its way past
     (test files deleted, assertions removed, tests skipped, trivially-true asserts).
  2. An optional second-opinion model, which MUST be from a different model
     family than the agent that produced the change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

TEST_PATH = re.compile(r"(^|/)(tests?/|test_[^/]*\.py$|[^/]*_test\.py$|[^/]*\.spec\.[jt]s$)")
ASSERT = re.compile(r"^\s*(assert\b|self\.assert\w+\(|expect\()", re.M)
SKIP = re.compile(r"@(pytest\.mark\.skip|unittest\.skip)|\.skip\(|xit\(|pytest\.skip\(")
TRIVIAL = re.compile(r"^\s*assert\s+(True|1)\s*$", re.M)


@dataclass
class Change:
    """One file in a proposed change. old=None means new file; new=None means deleted."""
    path: str
    old: str | None
    new: str | None


@dataclass
class Verdict:
    approved: bool
    findings: list[str] = field(default_factory=list)
    second_opinion: str | None = None


def model_family(model: str) -> str:
    m = model.lower()
    for fam in ("claude", "gpt", "gemini", "llama", "mistral", "qwen", "deepseek", "phi"):
        if fam in m:
            return fam
    return m


def deterministic_checks(changes: list[Change]) -> list[str]:
    findings = []
    for c in changes:
        if not TEST_PATH.search(c.path):
            continue
        if c.new is None and c.old is not None:
            findings.append(f"BLOCK: test file deleted: {c.path}")
            continue
        old, new = c.old or "", c.new or ""
        removed = len(ASSERT.findall(old)) - len(ASSERT.findall(new))
        if c.old is not None and removed > 0:
            findings.append(f"BLOCK: {removed} assertion(s) removed from {c.path}")
        if len(SKIP.findall(new)) > len(SKIP.findall(old)):
            findings.append(f"BLOCK: test(s) newly skipped in {c.path}")
        if len(TRIVIAL.findall(new)) > len(TRIVIAL.findall(old)):
            findings.append(f"BLOCK: trivially-true assertion added in {c.path}")
    return findings


def verify(changes: list[Change], producer_model: str,
           critic: Callable[[str], str] | None = None,
           critic_model: str | None = None) -> Verdict:
    findings = deterministic_checks(changes)
    second = None
    if critic is not None:
        if critic_model is None:
            raise ValueError("critic_model is required so family independence can be checked")
        if model_family(critic_model) == model_family(producer_model):
            findings.append(
                f"BLOCK: critic '{critic_model}' is the same model family as producer "
                f"'{producer_model}' — not an independent check"
            )
        else:
            summary = "\n".join(
                f"--- {c.path}\nOLD:\n{c.old}\nNEW:\n{c.new}" for c in changes
            )
            second = critic(
                "You are an independent reviewer. Reply 'APPROVE' or 'REJECT: <reason>'. "
                "Reject any change that weakens tests or security controls.\n" + summary
            )
            if not second.strip().upper().startswith("APPROVE"):
                findings.append(f"BLOCK: second-opinion model rejected: {second.strip()}")
    return Verdict(approved=not findings, findings=findings, second_opinion=second)
