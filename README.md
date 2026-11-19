# AgentGuard — treating AI agents as insider risk

![tests](https://github.com/piyushppd/agentguard/actions/workflows/tests.yml/badge.svg)

A small, dependency-free Python reference build that turns three ideas from
Satya Nadella's Pragmatic Engineer interview (Nov 2026) into working controls:

| Idea from the episode | What AgentGuard implements |
|---|---|
| "Treat agents as insider risk" | Agents are non-human identities with an accountable human owner, least-privilege scopes, expiry, and JIT elevation approved by someone other than the owner |
| "Audited, tamper-proof logs of agent reasoning" | Every tool call is logged *with the agent's stated reasoning* in an HMAC hash chain; any edit, deletion or reordering is detected and located |
| "Verification is the hard part" / models delete failing tests | An independent verifier blocks test deletion, removed assertions, skipped tests and `assert True`, and refuses a second-opinion model from the same family as the producer. Commits can't pass the gate without an approved verdict |
| Access certification for agent populations | A review campaign that flags orphaned delegation, unused scopes, SoD conflicts and repeated denied calls, using audit-log evidence rather than rubber-stamping |

## Run it

```bash
python3 demo.py                      # scenario: 3 agents in a bank ops team
python3 tests/test_agentguard.py     # 13 unit tests
```

Python 3.10+ only, nothing to install. Outputs land in `out/`:
`audit.jsonl` (the hash chain) and `certification_report.md`.
A sample report is in [`docs/`](docs/sample_certification_report.md).

## What the demo shows

1. An owner can't hand an agent authority they don't hold themselves.
2. A sensitive PII export stops at NEEDS_APPROVAL; the owner can't self-approve; a security reviewer grants a 15-minute JIT window.
3. A prompt injection in a ticket makes the triage agent try `grant_admin` three times. Every attempt is denied and logged, and the attempts show up in the certification.
4. The release agent "fixes" a build by deleting the failing test. The verifier blocks it, rejects a same-family critic, and the gate refuses the commit. A real fix approved by a different model family goes through.
5. The agent's owner leaves the bank and nobody deprovisions the agent. The gate denies anyway, because authority is checked against the *current* owner.
6. Certification: release-agent → REVOKE_OR_REASSIGN, invoice-agent → REMEDIATE_SOD, triage-agent → REDUCE.
7. Tamper test: editing one log line to hide the PII export is caught at the exact record.

## Plug in a real model

`agentguard/llm.py` has a stdlib-only Claude critic (`ANTHROPIC_API_KEY`) and a
commented Ollama example for a local open model. Use one family to produce and
another to critique.

## Build roadmap (each step = one more hands-on skill)

1. **Now:** run the demo, change the policies, break it, read the code.
2. **Real agent in the loop:** replace the scripted calls with a Claude or local Llama agent whose tool calls go through `PolicyGate.call`. Expose the gate as an MCP server so any MCP client must pass through it.
3. **Cloud-native hardening (your AWS sandbox):** HMAC key in KMS, chain head anchored to S3 Object Lock every N records, agent identities as IAM roles with session tags, JIT through a Step Functions approval.
4. **Private evals:** a set of attack scenarios (prompt injection, reward hacking, data exfiltration) scored against two or three models. This is Nadella's "swap any model and still pass your private evals" test.
5. **Agentic GRC:** have an agent collect control evidence (MAS TRM style) through the same gate, with the certification report as its output.

## Honest framing

This is a personal reference build, not a production system or a client deliverable.
It runs simulated agents.
