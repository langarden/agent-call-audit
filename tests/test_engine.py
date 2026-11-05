"""Test suite for agent-call-audit (stdlib unittest, no third-party deps).

    python -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from audit_guard import AuditGuard, AuditRequest, AuditTrail, RuleSet, hash_payload  # noqa: E402

ZERO_HASH = "0" * 64


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def build_guard(clock, fence=None, **kwargs) -> AuditGuard:
    ruleset = RuleSet.demo()
    if fence is not None:
        ruleset.fence.per_call, ruleset.fence.per_day, ruleset.fence.per_month = fence
    guard = AuditGuard(ruleset, trail=AuditTrail(), clock=clock, **kwargs)
    guard.register_caller(
        "caller-demo",
        "sekret",
        capabilities=["data.lookup", "content.publish", "money.transfer"],
        max_action="spend",
        max_data_class="internal",
    )
    return guard


class GuardTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.guard = build_guard(self.clock)

    # ------------------------------------------------------------------ helper
    def req(self, **overrides) -> AuditRequest:
        payload = overrides.pop("payload", None)
        base = dict(
            caller_id="caller-demo",
            credential="sekret",
            target_capability="data.lookup",
            action_type="read",
            data_class="public",
            request_hash=hash_payload(payload) if payload is not None else ZERO_HASH,
            nonce=uuid.uuid4().hex,
            timestamp=self.clock(),
            idempotency_key=None,
            amount=None,
            payload=payload,
        )
        base.update(overrides)
        return AuditRequest(**base)

    # ------------------------------------------------------------ happy path
    def test_allow_basic_read(self):
        verdict = self.guard.evaluate(self.req())
        self.assertEqual(verdict.decision, "allow")
        self.assertEqual(verdict.reason_code, "ALLOWED")
        self.assertEqual(verdict.risk_level, "low")
        self.assertTrue(verdict.trace_id)

    # ------------------------------------------------------------------ auth
    def test_auth_failed_wrong_credential(self):
        verdict = self.guard.evaluate(self.req(credential="wrong"))
        self.assertEqual(verdict.decision, "deny")
        self.assertEqual(verdict.reason_code, "ERR_AUTH_FAILED")

    def test_auth_failed_unknown_caller(self):
        verdict = self.guard.evaluate(self.req(caller_id="ghost"))
        self.assertEqual(verdict.reason_code, "ERR_AUTH_FAILED")

    # ------------------------------------------------------------ capability
    def test_unknown_capability(self):
        verdict = self.guard.evaluate(self.req(target_capability="fs.wipe"))
        self.assertEqual(verdict.reason_code, "ERR_UNKNOWN_CAPABILITY")

    def test_capability_not_granted(self):
        self.guard.register_caller("caller-narrow", "pw", capabilities=["data.lookup"])
        verdict = self.guard.evaluate(
            self.req(caller_id="caller-narrow", credential="pw", target_capability="content.publish")
        )
        self.assertEqual(verdict.reason_code, "ERR_CAPABILITY_NOT_GRANTED")

    # ---------------------------------------------------------------- integrity
    def test_hash_format_invalid(self):
        verdict = self.guard.evaluate(self.req(request_hash="not-a-hash"))
        self.assertEqual(verdict.reason_code, "ERR_HASH_MISMATCH")

    def test_hash_payload_mismatch(self):
        verdict = self.guard.evaluate(
            self.req(payload={"a": 1}, request_hash=hash_payload({"a": 2}))
        )
        self.assertEqual(verdict.reason_code, "ERR_HASH_MISMATCH")

    def test_hash_payload_match_allows(self):
        payload = {"q": "hello"}
        verdict = self.guard.evaluate(self.req(payload=payload, request_hash=hash_payload(payload)))
        self.assertEqual(verdict.decision, "allow")

    def test_stale_request(self):
        verdict = self.guard.evaluate(self.req(timestamp=self.clock() - 3600))
        self.assertEqual(verdict.reason_code, "ERR_STALE_REQUEST")

    # ------------------------------------------------------- replay / retries
    def test_replay_nonce_denied(self):
        nonce = uuid.uuid4().hex
        self.assertEqual(self.guard.evaluate(self.req(nonce=nonce)).decision, "allow")
        verdict = self.guard.evaluate(self.req(nonce=nonce))
        self.assertEqual(verdict.reason_code, "ERR_REPLAY")

    def test_idempotency_returns_cached_verdict(self):
        first = self.guard.evaluate(self.req(idempotency_key="idem-1"))
        second = self.guard.evaluate(self.req(idempotency_key="idem-1"))
        self.assertEqual(first.trace_id, second.trace_id)
        self.assertTrue(second.idempotent_replay)

    # --------------------------------------------------------------- priority
    def test_red_line_beats_permission_matrix(self):
        # caller-demo may not touch "restricted" data at all, yet the red line must win.
        verdict = self.guard.evaluate(
            self.req(target_capability="content.publish", action_type="outbound", data_class="restricted")
        )
        self.assertEqual(verdict.reason_code, "ERR_RED_LINE")
        self.assertIn("DEMO-RL-001", verdict.matched_rules)

    def test_permission_action_denied(self):
        self.guard.register_caller(
            "caller-low", "pw", capabilities=["content.publish"], max_action="read", max_data_class="internal"
        )
        verdict = self.guard.evaluate(
            self.req(caller_id="caller-low", credential="pw", target_capability="content.publish", action_type="write")
        )
        self.assertEqual(verdict.reason_code, "ERR_PERMISSION_ACTION")

    def test_permission_data_class_denied(self):
        verdict = self.guard.evaluate(self.req(data_class="restricted"))
        self.assertEqual(verdict.reason_code, "ERR_PERMISSION_DATA_CLASS")

    # -------------------------------------------------------------- fence caps
    def test_fence_per_call_exceeded(self):
        verdict = self.guard.evaluate(
            self.req(target_capability="money.transfer", action_type="spend", amount=600.0)
        )
        self.assertEqual(verdict.reason_code, "ERR_LIMIT_EXCEEDED")
        self.assertIn("fence:per_call", verdict.matched_rules)

    def test_fence_per_day_then_near_limit_human(self):
        for _ in range(4):  # 4 * 400 = 1600 of a 2000/day fence
            self.assertEqual(
                self.guard.evaluate(
                    self.req(target_capability="money.transfer", action_type="spend", amount=400.0)
                ).decision,
                "allow",
            )
        near = self.guard.evaluate(
            self.req(target_capability="money.transfer", action_type="spend", amount=400.0)
        )
        self.assertEqual(near.decision, "human")
        self.assertEqual(near.reason_code, "HUMAN_LIMIT_NEAR_THRESHOLD")

        over = self.guard.evaluate(
            self.req(target_capability="money.transfer", action_type="spend", amount=400.0)
        )
        self.assertEqual(over.reason_code, "ERR_LIMIT_EXCEEDED")

    def test_quota_reservation_is_atomic_under_concurrency(self):
        guard = build_guard(self.clock, fence=(500.0, 2000.0, 5000.0))
        results = []
        lock = threading.Lock()

        def worker():
            verdict = guard.evaluate(
                self.req(target_capability="money.transfer", action_type="spend", amount=400.0)
            )
            with lock:
                results.append(verdict.decision)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(results.count("allow"), 4)
        self.assertEqual(results.count("human"), 1)
        self.assertEqual(results.count("deny"), 5)
        self.assertEqual(guard.quota.usage("caller-demo", self.clock())["day"], 2000.0)

    # -------------------------------------------------------- human in the loop
    def test_high_risk_routes_to_human_then_approved(self):
        self.guard.register_caller(
            "caller-broad", "pw", capabilities=["content.publish"], max_action="outbound", max_data_class="restricted"
        )
        verdict = self.guard.evaluate(
            self.req(caller_id="caller-broad", credential="pw", target_capability="content.publish",
                     action_type="outbound", data_class="sensitive")
        )
        self.assertEqual(verdict.decision, "human")
        self.assertEqual(verdict.reason_code, "HUMAN_REVIEW_REQUIRED")
        self.assertIsNotNone(verdict.expires_at)
        self.assertEqual(self.guard.pending_count(), 1)

        resolved = self.guard.resolve(verdict.trace_id, approve=True)
        self.assertEqual(resolved.decision, "allow")
        self.assertEqual(resolved.reason_code, "HUMAN_APPROVED")
        self.assertEqual(self.guard.pending_count(), 0)

    def test_human_timeout_denies_and_releases_quota(self):
        guard = build_guard(self.clock, fence=(2500.0, 2000.0, 5000.0))
        verdict = guard.evaluate(
            self.req(target_capability="money.transfer", action_type="spend", amount=1900.0)
        )
        self.assertEqual(verdict.decision, "human")
        self.assertEqual(guard.quota.usage("caller-demo", self.clock())["day"], 1900.0)

        self.clock.advance(guard.human_timeout + 1)
        expired = guard.expire_pending()
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].reason_code, "ERR_HUMAN_TIMEOUT")
        self.assertEqual(guard.quota.usage("caller-demo", self.clock())["day"], 0.0)

    def test_human_denied_releases_quota(self):
        guard = build_guard(self.clock, fence=(2500.0, 2000.0, 5000.0))
        verdict = guard.evaluate(
            self.req(target_capability="money.transfer", action_type="spend", amount=1900.0)
        )
        self.assertEqual(verdict.decision, "human")
        resolved = guard.resolve(verdict.trace_id, approve=False)
        self.assertEqual(resolved.reason_code, "HUMAN_DENIED")
        self.assertEqual(guard.quota.usage("caller-demo", self.clock())["day"], 0.0)

    # ------------------------------------------------------------- fail closed
    def test_fail_closed_on_internal_error(self):
        class Boom:
            id = "BOOM"

            def matches(self, req):
                raise RuntimeError("kaboom")

        self.guard.rules.red_lines = [Boom()]
        verdict = self.guard.evaluate(self.req())
        self.assertEqual(verdict.decision, "deny")
        self.assertEqual(verdict.reason_code, "ERR_INTERNAL_FAIL_CLOSED")

    # ------------------------------------------------------------------ trail
    def test_trail_hash_chain_detects_tampering(self):
        self.guard.evaluate(self.req())
        self.guard.evaluate(self.req())
        self.assertTrue(self.guard.trail.verify())
        self.assertEqual(len(self.guard.trail.entries), 2)

        self.guard.trail.entries[0]["decision"] = "deny"
        self.guard.trail._entries[0]["decision"] = "deny"  # tamper with the stored copy
        self.assertFalse(self.guard.trail.verify())

    def test_trail_never_stores_payload(self):
        payload = {"secret": "do-not-persist"}
        self.guard.evaluate(self.req(payload=payload, request_hash=hash_payload(payload)))
        blob = repr(self.guard.trail.entries)
        self.assertNotIn("do-not-persist", blob)
        self.assertIn(hash_payload(payload), blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
