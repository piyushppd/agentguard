import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentguard import (Agent, AuditLog, Change, Decision, Directory, Human,
                        PolicyGate, ToolSpec, run_campaign, verify)


def setup():
    d = Directory()
    d.add_human(Human("o", "Owner", "X", {"a:read", "p:create", "p:approve", "s:export"}))
    d.add_human(Human("r", "Reviewer", "Sec", set()))
    d.register_agent(Agent("ag", "t", "o", "claude", {"a:read", "p:create", "p:approve"}))
    tmp = tempfile.mkdtemp()
    log = AuditLog(Path(tmp) / "a.jsonl", os.urandom(16))
    g = PolicyGate(d, log)
    g.register_tool(ToolSpec("read", "a:read"), lambda: "ok")
    g.register_tool(ToolSpec("export", "s:export", sensitive=True), lambda: "ok")
    g.register_tool(ToolSpec("pay", "p:create", max_per_minute=2), lambda: "ok")
    return d, log, g


class Gate(unittest.TestCase):
    def test_allow_and_unknown(self):
        d, log, g = setup()
        self.assertEqual(g.call("ag", "read", {}, "r").decision, Decision.ALLOW)
        self.assertEqual(g.call("nope", "read", {}, "r").decision, Decision.DENY)

    def test_sensitive_needs_jit_and_no_self_approval(self):
        d, log, g = setup()
        self.assertEqual(g.call("ag", "export", {}, "r").decision, Decision.NEEDS_APPROVAL)
        with self.assertRaises(PermissionError):
            d.grant_jit("ag", "s:export", "o", "self")
        d.grant_jit("ag", "s:export", "r", "ok")
        self.assertEqual(g.call("ag", "export", {}, "r").decision, Decision.ALLOW)

    def test_owner_offboarding_revokes_agent(self):
        d, log, g = setup()
        d.offboard_human("o")
        res = g.call("ag", "read", {}, "r")
        self.assertEqual(res.decision, Decision.DENY)
        self.assertIn("no longer active", res.reason)

    def test_rate_limit(self):
        d, log, g = setup()
        out = [g.call("ag", "pay", {}, "r").decision for _ in range(3)]
        self.assertEqual(out[-1], Decision.DENY)

    def test_commit_needs_approved_verdict(self):
        d, log, g = setup()
        g.register_tool(ToolSpec("commit", "a:read", requires_verification=True), lambda: "ok")
        self.assertEqual(g.call("ag", "commit", {}, "r").decision, Decision.DENY)
        bad = verify([Change("tests/test_x.py", "assert 1\n", None)], "claude")
        self.assertEqual(g.call("ag", "commit", {}, "r", verdict=bad).decision, Decision.DENY)
        ok = verify([Change("src/x.py", "a", "b")], "claude")
        self.assertEqual(g.call("ag", "commit", {}, "r", verdict=ok).decision, Decision.ALLOW)

    def test_cannot_delegate_excess(self):
        d, _, _ = setup()
        with self.assertRaises(ValueError):
            d.register_agent(Agent("x", "t", "r", "gpt", {"a:read"}))


class Audit(unittest.TestCase):
    def test_tamper_and_deletion_detected(self):
        d, log, g = setup()
        for _ in range(3):
            g.call("ag", "read", {}, "r")
        self.assertTrue(log.verify().ok)
        lines = log.path.read_text().splitlines()
        log.path.write_text("\n".join([lines[0], lines[2]]) + "\n")
        r = log.verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.broken_at, 2)

    def test_edit_detected(self):
        d, log, g = setup()
        g.call("ag", "read", {}, "honest")
        log.path.write_text(log.path.read_text().replace("honest", "edited"))
        self.assertEqual(log.verify().reason, "record content altered")


class Verifier(unittest.TestCase):
    def test_deleted_test_blocked(self):
        v = verify([Change("tests/test_x.py", "assert f()==1\n", None)], "claude")
        self.assertFalse(v.approved)

    def test_removed_assert_and_skip(self):
        old = "def test_a():\n    assert a()\n"
        new = "import pytest\n@pytest.mark.skip\ndef test_a():\n    pass\n"
        v = verify([Change("tests/test_a.py", old, new)], "claude")
        self.assertEqual(len(v.findings), 2)

    def test_same_family_critic_rejected(self):
        v = verify([Change("src/a.py", "x", "y")], "claude-opus",
                   critic=lambda p: "APPROVE", critic_model="claude-haiku")
        self.assertFalse(v.approved)

    def test_independent_critic_ok(self):
        v = verify([Change("src/a.py", "x", "y")], "claude-opus",
                   critic=lambda p: "APPROVE", critic_model="llama3")
        self.assertTrue(v.approved)


class Certification(unittest.TestCase):
    def test_recommendations(self):
        d, log, g = setup()
        g.call("ag", "read", {}, "r")
        items = run_campaign(d, log, {"read": "a:read", "pay": "p:create"},
                             sod_pairs=[("p:create", "p:approve")])
        self.assertEqual(items[0].recommendation, "REMEDIATE_SOD")
        d.offboard_human("o")
        items = run_campaign(d, log, {"read": "a:read"})
        self.assertEqual(items[0].recommendation, "REVOKE_OR_REASSIGN")


def deleg_setup():
    from agentguard import TokenService
    d = Directory()
    d.add_human(Human("u", "User", "CS", {"t:read", "r:create"}))
    d.add_human(Human("o", "Owner", "Ops", {"t:read", "r:create", "p:create"}))
    d.register_agent(Agent("a", "triage", "o", "gpt-4o", {"t:read"}))
    d.register_agent(Agent("b", "refund", "o", "gemini", {"r:create"}))
    d.register_agent(Agent("c", "pay", "o", "claude", {"p:create"}))
    log = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl", os.urandom(16))
    ts = TokenService(d, os.urandom(16), audit=log)
    g = PolicyGate(d, log, tokens=ts)
    g.register_tool(ToolSpec("read", "t:read"), lambda **k: "ok")
    g.register_tool(ToolSpec("refund", "r:create"), lambda **k: "ok")
    return d, log, ts, g


class Delegation(unittest.TestCase):
    def test_scope_is_intersection_and_chain_attenuates(self):
        from agentguard import DelegationError
        d, log, ts, g = deleg_setup()
        t1 = ts.exchange_user_token("u", "a", {"t:read", "r:create", "p:create"},
                                    "resolve", {"max_amount": 200})
        self.assertEqual(t1.scopes, {"t:read", "r:create"})  # p:create: user lacks it
        t2 = ts.exchange_for_agent(t1, "b", {"r:create"}, tighten={"max_amount": 500})
        self.assertEqual(t2.limits["max_amount"], 200)       # can only tighten
        self.assertEqual(t2.claims()["act"], {"sub": "b", "act": {"sub": "a"}})
        with self.assertRaises(DelegationError):
            ts.exchange_for_agent(t1, "c", {"p:create"})     # expansion refused
        with self.assertRaises(DelegationError):
            ts.exchange_for_agent(t2, "a", {"r:create"})     # loop refused

    def test_token_enforced_on_every_use(self):
        d, log, ts, g = deleg_setup()
        t1 = ts.exchange_user_token("u", "a", {"t:read", "r:create"}, "x", {"max_amount": 200})
        t2 = ts.exchange_for_agent(t1, "b", {"r:create"})
        self.assertEqual(g.call("b", "refund", {"amount": 100}, "r", token=t2).decision, Decision.ALLOW)
        self.assertEqual(g.call("b", "refund", {"amount": 300}, "r", token=t2).decision, Decision.DENY)
        self.assertEqual(g.call("a", "refund", {"amount": 1}, "r", token=t2).decision, Decision.DENY)
        d.offboard_human("u")
        res = g.call("b", "refund", {"amount": 100}, "r", token=t2)
        self.assertIn("no longer active", res.reason)

    def test_revoking_parent_kills_child_and_forgery_detected(self):
        import dataclasses
        d, log, ts, g = deleg_setup()
        t1 = ts.exchange_user_token("u", "a", {"t:read", "r:create"}, "x")
        t2 = ts.exchange_for_agent(t1, "b", {"r:create"})
        forged = dataclasses.replace(t2, scopes=frozenset({"r:create", "t:read", "p:create"}))
        self.assertEqual(ts.validate(forged)[1], "token signature invalid")
        ts.revoke(t1.token_id)
        self.assertFalse(ts.validate(t2)[0])

    def test_trace_and_siem_export(self):
        from agentguard import export_jsonl
        d, log, ts, g = deleg_setup()
        t1 = ts.exchange_user_token("u", "a", {"t:read"}, "x")
        g.call("a", "read", {}, "r", token=t1)
        out = Path(tempfile.mkdtemp()) / "s.jsonl"
        self.assertEqual(export_jsonl(log, out), 2)
        ev = [__import__("json").loads(l) for l in out.read_text().splitlines()][-1]
        self.assertEqual(ev["actor"]["user"]["uid"], "u")
        self.assertEqual(ev["metadata"]["correlation_uid"], t1.trace_id)


class LeastAgencyAndContainment(unittest.TestCase):
    def test_purpose_bound_and_risk_adaptive(self):
        from agentguard import amount_over
        d = Directory()
        d.add_human(Human("o", "O", "X", {"p:create", "x:read"}))
        d.add_human(Human("r", "R", "Sec", set()))
        d.register_agent(Agent("ag", "pay", "o", "claude", {"p:create", "x:read"},
                               allowed_tools={"pay"}))
        log = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl", os.urandom(16))
        g = PolicyGate(d, log)
        g.register_tool(ToolSpec("pay", "p:create", approval_rule=amount_over(1000)), lambda **k: 1)
        g.register_tool(ToolSpec("peek", "x:read"), lambda **k: 1)
        self.assertEqual(g.call("ag", "pay", {"amount": 10}, "r").decision, Decision.ALLOW)
        self.assertEqual(g.call("ag", "pay", {"amount": 5000}, "r").decision, Decision.NEEDS_APPROVAL)
        self.assertEqual(g.call("ag", "peek", {}, "r").decision, Decision.DENY)
        d.grant_jit("ag", "p:create", "r", "ok")
        self.assertEqual(g.call("ag", "pay", {"amount": 5000}, "r").decision, Decision.ALLOW)

    def test_auto_containment_and_unregistered(self):
        from agentguard import unregistered_identities
        d, log, g = setup()
        for _ in range(3):
            g.call("ag", "nope_tool", {}, "r")
        self.assertTrue(d.agents["ag"].suspended)
        self.assertEqual(g.call("ag", "read", {}, "r").decision, Decision.DENY)
        self.assertTrue(any(r["event"] == "containment" for r in log.records()))
        g.call("ghost", "read", {}, "r")
        self.assertEqual(unregistered_identities(d, log), {"ghost": 1})
        items = run_campaign(d, log, {"read": "a:read"})
        self.assertEqual(items[0].recommendation, "CONTAINED")

    def test_event_triggered_review_scope(self):
        d, log, g = setup()
        d.register_agent(Agent("ag2", "t", "r", "gpt", set()))
        affected = d.offboard_human("o")
        self.assertEqual(affected, ["ag"])
        items = run_campaign(d, log, {}, agent_ids=affected)
        self.assertEqual([i.agent_id for i in items], ["ag"])


if __name__ == "__main__":
    unittest.main()
