# Agent Access Certification — Campaign Report

Generated: 2026-11-19 03:54 UTC  
Audit chain integrity: VERIFIED  
Agents in scope: 3  
Outcome: REDUCE 1, REMEDIATE_SOD 1, REVOKE_OR_REASSIGN 1

| Agent | Owner | Model | Recommendation | Unused scopes | Denied calls |
|---|---|---|---|---|---|
| release-agent | carol (inactive) | llama-3-70b | **REVOKE_OR_REASSIGN** | docs:read | 2 |
| invoice-agent | alice | claude-sonnet | **REMEDIATE_SOD** | payments:approve | 1 |
| triage-agent | dave | gpt-4o | **REDUCE** | crm:export | 3 |

## Evidence per agent

### release-agent — REVOKE_OR_REASSIGN
Purpose: Fix failing builds  
Granted: code:write, docs:read  
Used: code:write  
- Owner carol is inactive — delegated authority has lapsed.
- Identity expires in 9 days — confirm renewal or let lapse.

### invoice-agent — REMEDIATE_SOD
Purpose: Match invoices and raise payments  
Granted: docs:read, payments:approve, payments:create  
Used: docs:read, payments:create, pii:export  
- Holds both sides of SoD pair(s): [('payments:create', 'payments:approve')].

### triage-agent — REDUCE
Purpose: Triage customer tickets  
Granted: crm:export, tickets:read, tickets:write  
Used: tickets:read, tickets:write  
- Scopes unused in the review window: ['crm:export'].
- 3 denied/escalated calls — review agent behaviour and prompt.
