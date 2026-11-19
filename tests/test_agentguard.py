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


if __name__ == "__main__":
    unittest.main()
