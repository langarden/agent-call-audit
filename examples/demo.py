"""Scripted walkthrough of agent-call-audit.

    python examples/demo.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_guard import AuditGuard, AuditRequest, AuditTrail, RuleSet, hash_payload  # noqa: E402


def make_request(**over):
    payload = over.pop("payload", None)
    base = dict(
        caller_id="agent-demo",
        credential="demo-secret",
        target_capability="data.lookup",
        action_type="read",
        data_class="public",
        request_hash=hash_payload(payload) if payload is not None else "0" * 64,
        nonce=uuid.uuid4().hex,
        timestamp=time.time(),
        idempotency_key=None,
        amount=None,
        payload=None,
    )
    base.update(over)
    return AuditRequest(**base)


def main() -> int:
    trail_path = os.path.join(tempfile.mkdtemp(prefix="agent-call-audit-"), "audit.jsonl")
    guard = AuditGuard(RuleSet.demo(), trail=AuditTrail(trail_path))
    guard.register_caller(
        "agent-demo",
        "demo-secret",
        capabilities=["data.lookup", "content.publish", "money.transfer"],
        max_action="spend",
        max_data_class="internal",
    )

    cases = [
        ("plain read", dict()),
        ("read of restricted data", dict(data_class="restricted")),
        ("outbound of restricted data", dict(
            target_capability="content.publish", action_type="outbound", data_class="restricted")),
        ("small payment", dict(target_capability="money.transfer", action_type="spend", amount=300.0)),
        ("payment above per-call fence", dict(
            target_capability="money.transfer", action_type="spend", amount=900.0)),
        ("unknown capability", dict(target_capability="fs.delete-everything")),
    ]

    print("=" * 78)
    print("agent-call-audit demo".center(78))
    print("=" * 78)
    print("%-30s %-8s %-28s %s" % ("scenario", "verdict", "reason_code", "risk"))
    print("-" * 78)
    for label, overrides in cases:
        verdict = guard.evaluate(make_request(**overrides))
        print("%-30s %-8s %-28s %s" % (label, verdict.decision, verdict.reason_code, verdict.risk_level))

    # retry safety: same idempotency key -> cached verdict; same nonce -> replay denial
    first = guard.evaluate(make_request(idempotency_key="demo-idem-1"))
    retry = guard.evaluate(make_request(idempotency_key="demo-idem-1"))
    print("-" * 78)
    print("idempotent retry          : %s / %s (replay=%s, same trace=%s)"
          % (retry.decision, retry.reason_code, retry.idempotent_replay, retry.trace_id == first.trace_id))

    guard.evaluate(make_request(nonce="demo-nonce-fixed"))
    replay = guard.evaluate(make_request(nonce="demo-nonce-fixed"))
    print("same nonce again          : %s" % replay.reason_code)
    print("-" * 78)

    print("trail entries           : %d" % len(guard.trail.entries))
    print("trail hash-chain valid  : %s" % guard.trail.verify())
    print("payload persisted       : never (only request hash)")
    print("trail file              : %s" % trail_path)
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
