# Agent Access Certification — Campaign Report

Generated: 2026-11-19 04:27 UTC  
Trigger: scheduled  
Audit chain integrity: VERIFIED  
Agents in scope: 4  
Outcome: CERTIFY 1, CONTAINED 1, REMEDIATE_SOD 1, REVOKE_OR_REASSIGN 1

| Agent | Owner | Model | Recommendation | Unused scopes | Denied calls |
|---|---|---|---|---|---|
| release-agent | carol (inactive) | llama-3-70b | **REVOKE_OR_REASSIGN** | docs:read | 2 |
| triage-agent | dave | gpt-4o | **CONTAINED** | crm:export, tickets:write | 4 |
| invoice-agent | alice | claude-sonnet | **REMEDIATE_SOD** | docs:read, payments:approve | 2 |
| refund-agent | alice | gemini-2.5 | **CERTIFY** | — | 2 |

## Unregistered identities seen at the gate

Not in the registry, so no owner and no review obligation. Find, register with an owner, or block.

- `shadow-bot` — 1 call(s), all denied

## Evidence per agent

### release-agent — REVOKE_OR_REASSIGN
Purpose: Fix failing builds  
Granted: code:write, docs:read  
Used: code:write  
- Owner carol is inactive — delegated authority has lapsed.
- Identity expires in 9 days — confirm renewal or let lapse.

### triage-agent — CONTAINED
Purpose: Triage customer tickets  
Granted: crm:export, tickets:read, tickets:write  
Used: tickets:read  
- Suspended by the gate for repeatedly hitting its boundary — investigate prompt/inputs before reinstating.
- 4 denied/escalated calls — review agent behaviour and prompt.
- Acted on behalf of: ['erin'] (delegated tokens).

### invoice-agent — REMEDIATE_SOD
Purpose: Match invoices and raise payments  
Granted: docs:read, payments:approve, payments:create  
Used: payments:create  
- Holds both sides of SoD pair(s): [('payments:create', 'payments:approve')].

### refund-agent — CERTIFY
Purpose: Issue customer refunds  
Granted: refunds:create  
Used: refunds:create  
- All scopes evidenced by actual use; owner active.
- Acted on behalf of: ['erin'] (delegated tokens).
