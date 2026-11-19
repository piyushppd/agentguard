"""Tamper-evident audit log for agent actions *and* agent reasoning.

Nadella asked for "audited, tamper-proof logs of agent reasoning". This is
the simplest honest version: an append-only JSON-lines file where each
record carries an HMAC over (previous hash + record). Editing, deleting or
reordering any line breaks the chain from that point on, and verify()
reports exactly where.

Production upgrade path: write the chain head to WORM storage
(e.g. S3 Object Lock in compliance mode) or a transparency log every N
records, and keep the HMAC key in KMS/HSM rather than in the process.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from .identity import now

GENESIS = "0" * 64


@dataclass
class VerifyResult:
    ok: bool
    records: int
    broken_at: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, path: str | Path, key: bytes) -> None:
        self.path = Path(path)
        self.key = key
        self.path.touch(exist_ok=True)
        self._head = self._last_hash()

    def _last_hash(self) -> str:
        last = GENESIS
        for line in self.path.read_text().splitlines():
            if line.strip():
                last = json.loads(line)["hash"]
        return last

    def _mac(self, prev: str, body: dict) -> str:
        payload = prev + json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()

    def append(self, event: str, **fields) -> dict:
        body = {"ts": now().isoformat(), "event": event, **fields}
        rec = {**body, "prev": self._head, "hash": self._mac(self._head, body)}
        with self.path.open("a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        self._head = rec["hash"]
        return rec

    def records(self) -> list[dict]:
        return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def verify(self) -> VerifyResult:
        prev = GENESIS
        recs = self.path.read_text().splitlines()
        for i, line in enumerate(recs, start=1):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, len(recs), i, "unparseable record")
            body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
            if rec.get("prev") != prev:
                return VerifyResult(False, len(recs), i, "chain link broken (record removed or reordered)")
            if not hmac.compare_digest(rec.get("hash", ""), self._mac(prev, body)):
                return VerifyResult(False, len(recs), i, "record content altered")
            prev = rec["hash"]
        return VerifyResult(True, len(recs))
