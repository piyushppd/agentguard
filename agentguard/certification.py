"""Access certification campaign for an *agent* population.

Classic user access reviews break on agents in predictable ways. This
campaign targets four of them directly:
  1. Orphaned delegation – the human owner left, the agent still holds credentials.
  2. Standing over-privilege – scopes granted but never used (evidence: the audit log).
  3. Toxic combinations – one agent holding both sides of a segregation-of-duties pair.
  4. Behavioural signals – repeated DENY / NEEDS_APPROVAL hits, i.e. the agent
     keeps reaching for authority it doesn't have.

Each agent gets an evidence-backed recommendation the reviewer accepts or
overrides, instead of rubber-stamping a list of entitlements.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .audit import AuditLog
from .identity import Directory, now

DEFAULT_SOD_PAIRS = [
    ("payments:create", "payments:approve"),
    ("iam:grant", "iam:review"),
    ("code:write", "code:deploy_prod"),
]


@dataclass
class ReviewItem:
    agent_id: str
    owner_id: str
    owner_active: bool
    purpose: str
    model: str
    scopes: list[str]
    used_scopes: list[str]
    unused_scopes: list[str]
    sod_conflicts: list[tuple[str, str]]
    denied_attempts: int
    days_to_expiry: int
    recommendation: str
    rationale: list[str] = field(default_factory=list)


def run_campaign(directory: Directory, audit: AuditLog,
                 tool_scopes: dict[str, str],
                 sod_pairs=DEFAULT_SOD_PAIRS,
                 deny_threshold: int = 3) -> list[ReviewItem]:
    used: dict[str, set[str]] = defaultdict(set)
    denied: Counter = Counter()
    for r in audit.records():
        if r.get("event") != "tool_call":
            continue
        if r["decision"] == "ALLOW" and r["tool"] in tool_scopes:
            used[r["agent_id"]].add(tool_scopes[r["tool"]])
        elif r["decision"] in ("DENY", "NEEDS_APPROVAL"):
            denied[r["agent_id"]] += 1

    items = []
    for a in directory.agents.values():
        owner = directory.humans.get(a.owner_id)
        owner_active = bool(owner and owner.active)
        unused = sorted(a.scopes - used[a.agent_id])
        conflicts = [p for p in sod_pairs if p[0] in a.scopes and p[1] in a.scopes]
        days = (a.expires_at - now()).days
        why: list[str] = []

        if not owner_active:
            rec = "REVOKE_OR_REASSIGN"
            why.append(f"Owner {a.owner_id} is inactive — delegated authority has lapsed.")
        elif conflicts:
            rec = "REMEDIATE_SOD"
            why.append(f"Holds both sides of SoD pair(s): {conflicts}.")
        elif unused:
            rec = "REDUCE"
            why.append(f"Scopes unused in the review window: {unused}.")
        else:
            rec = "CERTIFY"
            why.append("All scopes evidenced by actual use; owner active.")

        if denied[a.agent_id] >= deny_threshold:
            why.append(f"{denied[a.agent_id]} denied/escalated calls — review agent behaviour and prompt.")
        if days < 14:
            why.append(f"Identity expires in {days} days — confirm renewal or let lapse.")

        items.append(ReviewItem(
            a.agent_id, a.owner_id, owner_active, a.purpose, a.model,
            sorted(a.scopes), sorted(used[a.agent_id]), unused, conflicts,
            denied[a.agent_id], days, rec, why,
        ))
    order = {"REVOKE_OR_REASSIGN": 0, "REMEDIATE_SOD": 1, "REDUCE": 2, "CERTIFY": 3}
    return sorted(items, key=lambda i: (order[i.recommendation], i.agent_id))


def to_markdown(items: list[ReviewItem], chain_ok: bool) -> str:
    counts = Counter(i.recommendation for i in items)
    lines = [
        "# Agent Access Certification — Campaign Report",
        "",
        f"Generated: {now():%Y-%m-%d %H:%M} UTC  ",
        f"Audit chain integrity: {'VERIFIED' if chain_ok else 'FAILED — evidence not trustworthy'}  ",
        f"Agents in scope: {len(items)}  ",
        "Outcome: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())),
        "",
        "| Agent | Owner | Model | Recommendation | Unused scopes | Denied calls |",
        "|---|---|---|---|---|---|",
    ]
    for i in items:
        owner = i.owner_id + ("" if i.owner_active else " (inactive)")
        lines.append(
            f"| {i.agent_id} | {owner} | {i.model} | **{i.recommendation}** | "
            f"{', '.join(i.unused_scopes) or '—'} | {i.denied_attempts} |"
        )
    lines += ["", "## Evidence per agent", ""]
    for i in items:
        lines.append(f"### {i.agent_id} — {i.recommendation}")
        lines.append(f"Purpose: {i.purpose}  ")
        lines.append(f"Granted: {', '.join(i.scopes)}  ")
        lines.append(f"Used: {', '.join(i.used_scopes) or 'none'}  ")
        for r in i.rationale:
            lines.append(f"- {r}")
        lines.append("")
    return "\n".join(lines)
