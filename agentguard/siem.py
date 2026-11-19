"""Export the audit trail as SIEM-ready JSON lines.

Field layout is *inspired by* OCSF's API Activity class (category 6,
class_uid 6003) so it maps easily into Splunk, Sentinel, QRadar or
Security Lake. It is not a validated OCSF schema implementation.

Each event answers the questions a detection or audit team asks:
which agent, acting for which human, through which delegation chain,
under which consent, made which call, what the policy decided and why,
and which workflow (trace) it belonged to.
"""
from __future__ import annotations

import json
from pathlib import Path

from .audit import AuditLog

STATUS = {"ALLOW": "Success", "DENY": "Failure", "NEEDS_APPROVAL": "Pending"}
DISPOSITION = {"ALLOW": "Allowed", "DENY": "Blocked", "NEEDS_APPROVAL": "Approval Required"}


def to_event(rec: dict) -> dict | None:
    base = {
        "time": rec["ts"],
        "metadata": {
            "product": {"name": "AgentGuard", "vendor_name": "reference build"},
            "uid": rec["hash"],
            "correlation_uid": rec.get("trace_id"),
            "log_integrity": {"prev_hash": rec["prev"], "hash": rec["hash"]},
        },
    }
    if rec["event"] == "tool_call":
        return {
            **base,
            "category_name": "Application Activity",
            "class_name": "API Activity",
            "class_uid": 6003,
            "activity_name": "Agent Tool Call",
            "status": STATUS[rec["decision"]],
            "disposition": DISPOSITION[rec["decision"]],
            "status_detail": rec["reason"],
            "api": {"operation": rec["tool"], "request": {"data": rec.get("args")}},
            "actor": {
                "app_name": rec["agent_id"],
                "model": rec.get("model"),
                "accountable_owner": rec.get("owner_id"),
                "user": {"uid": rec.get("subject")},          # originating human
                "delegation_chain": rec.get("act_chain"),
                "token_uid": rec.get("token_id"),
            },
            "unmapped": {
                "agent_reasoning": rec.get("reasoning"),
                "consent": rec.get("consent"),
                "parent_span": rec.get("parent_span"),
            },
        }
    if rec["event"] == "containment":
        return {**base, "class_name": "Detection Finding", "activity_name": "Agent Contained",
                "severity": "High", "finding": {"title": rec["reason"]},
                "actor": {"app_name": rec["agent_id"], "accountable_owner": rec.get("owner_id")}}
    if rec["event"] == "token_issued":
        return {**base, "class_name": "Authentication", "activity_name": "Delegated Token Issued",
                "actor": {"user": {"uid": rec["sub"]}, "delegation": rec["act"]},
                "unmapped": {"scope": rec["scope"], "consent": rec["consent"],
                             "constraints": rec["constraints"], "token_uid": rec["jti"]}}
    return None


def export_jsonl(audit: AuditLog, path: str | Path) -> int:
    n = 0
    with Path(path).open("w") as f:
        for rec in audit.records():
            ev = to_event(rec)
            if ev:
                f.write(json.dumps(ev, default=str) + "\n")
                n += 1
    return n
