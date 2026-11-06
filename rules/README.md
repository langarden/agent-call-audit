# Rules

Rule data is **JSON, not code**. `RuleSet.from_json` loads it; changing rules never
requires touching the engine.

## Layers and precedence

```
red_lines ──┐
fence ──────┼──► strictest wins ──► allow / deny / human
permission ─┘
```

1. **red_lines** — absolute prohibitions, highest priority (e.g. outbound of restricted data).
2. **fence** — quota reservations (`per_call` / `per_day` / `per_month`), atomically reserved.
3. **permission matrix** — capability + `max_action` + `max_data_class` per caller.

Conflicts resolve to the **strictest** result: a red line beats a permission-matrix
allow every time.

## Schema sketch

```json
{
  "red_lines": [
    {"id": "DEMO-RL-001", "description": "outbound of restricted data",
     "action_types": ["outbound"], "data_classes": ["restricted"]}
  ],
  "fence": {"per_call": 500.0, "per_day": 2000.0, "per_month": 5000.0},
  "permissions": [
    {"caller": "agent-7", "credential": "<hash>", "capabilities": ["data.lookup"],
     "max_action": "read", "max_data_class": "internal"}
  ]
}
```

## How to add a rule

- Red line: add an entry to `red_lines` with the offending `action_types` / `data_classes`.
- Quota: tune the `fence` numbers; reservation stays atomic.
- Permission: add a `permissions` row for the caller; **redact the credential hash** before committing.

See `examples/` for a live ruleset. Never commit a plaintext credential.
