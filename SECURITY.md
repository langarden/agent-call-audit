# Security Policy

## Reporting a vulnerability

Report privately to **2307788504@qq.com** (same as the README contact). Do **not**
open a public issue for a suspected vulnerability.

## Design posture

- **Fail-closed**: unknown caller / unknown capability / bad hash / stale timestamp /
  any internal error ⇒ `deny`. No fail-open code path exists by design.
- **No payload persistence**: only request hashes are stored, never payload content.
- **Replay defence**: single-use nonces plus idempotency keys.
- **Human-in-the-loop**: high-risk actions require human approval with a hard timeout
  that resolves to `deny`.

## Scope

This is a **reference implementation**, not a hardened product. Review it against your
own threat model before any production use. It does not execute tool calls, does not
replace your IAM, and does not decide business policy.
