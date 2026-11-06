# agent-call-audit

**A tiny, dependency-free guardrail layer for agent tool calls — with a tamper-evident audit trail.**

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT">
  <img src="https://img.shields.io/badge/tests-23-green" alt="23 tests">
  <img src="https://img.shields.io/badge/dependencies-zero-green" alt="zero deps">
</p>

> ⚠️ This is the **generic, de-identified edition**. It contains no vendor-specific
> rules, no private data and no personal identifiers. Rules ship as examples only.

---

## Why

Agent frameworks are getting good at *doing things* (file writes, outbound messages,
payments) and bad at *proving what was allowed and why*. This package is the missing
middle: a single synchronous call that decides

```
allow | deny | human
```

for every tool call, refuses to fail open, and writes a hash-chained audit record that
a third party can verify offline.

## Design invariants

| # | Invariant | Where |
|:-:|:---|:---|
| 1 | **Rule priority: red lines > fence limits > permission matrix**; on conflict the most severe outcome wins | `engine.AuditGuard._evaluate` |
| 2 | **Fail-closed**: unknown caller / unknown capability / bad hash / stale timestamp / any internal error ⇒ `deny` | `engine.evaluate` |
| 3 | **Caller identity is bound to a credential** — a caller id string is never enough | `register_caller` |
| 4 | **Replay & retry defence**: single-use nonces; idempotency keys return the cached verdict | `_evaluate` steps 5–6 |
| 5 | **Atomic quota reservation**: concurrent calls can never overshoot per-call / per-day / per-month caps | `engine.QuotaBook` |
| 6 | **Human-in-the-loop** for high risk, with a hard timeout that resolves to `deny` | `resolve`, `expire_pending` |
| 7 | **Privacy by default**: only the request *hash* is persisted — payload content never is | `_finalize` |
| 8 | **Tamper-evident trail**: append-only JSONL with a SHA-256 hash chain, verifiable offline | `AuditTrail.verify` |

## Quick start

```bash
python examples/demo.py                       # scripted walkthrough
python -m unittest discover -s tests -t . -v  # 23 tests, no third-party deps
```

```python
from audit_guard import AuditGuard, AuditRequest, RuleSet, AuditTrail, hash_payload

guard = AuditGuard(RuleSet.demo(), trail=AuditTrail("audit.jsonl"))
guard.register_caller("agent-7", "s3cret", capabilities=["data.lookup"],
                      max_action="read", max_data_class="internal")

verdict = guard.evaluate(AuditRequest(
    caller_id="agent-7", credential="s3cret", target_capability="data.lookup",
    action_type="read", data_class="public",
    request_hash=hash_payload({"q": "hello"}), payload={"q": "hello"},
    nonce="n-1", timestamp=1_800_000_000.0,
))
print(verdict.decision, verdict.reason_code)     # allow ALLOWED
print(guard.trail.verify())                       # True
```

## Rule file

Rules are data, not code — see `rules/rules.example.json` (loaded via
`RuleSet.from_json`).

```json
{
  "red_lines": [
    {"id": "DEMO-RL-001", "description": "outbound of restricted data",
     "action_types": ["outbound"], "data_classes": ["restricted"]}
  ],
  "fence": {"per_call": 500.0, "per_day": 2000.0, "per_month": 5000.0}
}
```

## Transports

`protocol.py` implements only the **semantic layer** (`audit.call`,
`audit.resolve`, `audit.pending`) over stdio JSON lines. Binding it to MCP, A2A or
plain HTTP is a transport concern and deliberately left to the caller, so the same
rule engine runs locally, in a sandbox, or behind a gateway without change.

## Status & non-goals

* Status: **reference implementation**, not a hardened product. No SLA.
* Non-goals: it does not execute the tool call, does not store payloads, does not
  replace your IAM, and does not decide business policy for you — you write the rules.
* Security review is the user's responsibility before any production use.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules (fail-closed first,
no new dependencies, de-identified commits, tests green). Found a security issue?
See [SECURITY.md](SECURITY.md).

## License

MIT — see `LICENSE`.

## Contact

**Furitong Digital Workspace (福瑞通 · 数字工作台)** — automation workbench, AI-assisted
delivery. Business enquiries: **2307788504@qq.com**. No financial advice, no legal
opinions, no crypto-related work.

---
*Copyright (c) 2026 Furitong Digital Workspace. MIT licensed.*
