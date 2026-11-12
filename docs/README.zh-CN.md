# agent-call-audit（中文）

> **Agent 工具调用的极简、零依赖护栏层** —— 带可防篡改的审计留痕。
> **默认拒绝（fail-closed）：任何不确定 → deny。**

```bash
pip install agent-call-audit          # 零依赖，Python 3.9+
```

<a href="https://gitcode.com/gcw_MKhSyoGN/agent-call-audit"><img src="https://img.shields.io/badge/GitCode-gcw_MKhSyoGN%2Fagent-call-audit-blue" alt="GitCode"></a>
<a href="https://github.com/langarden/agent-call-audit"><img src="https://img.shields.io/badge/GitHub-langarden%2Fagent-call-audit-black" alt="GitHub"></a>

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Tests](https://img.shields.io/badge/tests-23%20passed-green)
![Deps](https://img.shields.io/badge/runtime%20deps-0-green)
![Status](https://img.shields.io/badge/status-research%20prototype-orange)

> ⚠️ 这是**通用、去标识版本**。不含任何厂商特定规则、私有数据或个人标识；规则仅以示例形式提供。

---

Agent 框架越来越擅长"做事"（写文件、外发消息、支付），却越来越难"证明"什么被允许、为什么。本包补上缺失的一环：**一次同步调用**，为每次工具调用裁决：

```
allow | deny | human
```

拒绝故障开放（fail-open），并写入一条**可被第三方离线验证的哈希链审计记录**。

## 产品家族（Verifiable-agent 家族）

| 仓库 | 角色 |
|:--|:--|
| **agent-call-audit** | Agent 调用**审计引擎**（本仓库） |
| agent-memory-ledger | 可验证**记忆层** |
| agent-audit-gateway | 引擎的 HTTP **网关** |
| agent-route-grid | 多 Agent **路由编排** |

## 8 条设计不变量

1. 规则优先级：红线 > 围栏限额 > 权限矩阵；冲突取最严
2. **fail-closed**：未知调用者/未知能力/坏哈希/过期时间戳/内部错误 ⇒ deny
3. 调用者身份绑定凭据——仅一个 id 字符串永远不够
4. 重放/重试防御：单次 nonce；幂等键返回缓存裁决
5. 原子配额预留：并发调用永不超过每笔/每日/每月限额
6. 高风险人工介入，带硬超时，超时解析为 deny
7. **默认隐私**：只持久化请求 *哈希*——payload 内容永不落盘
8. 防篡改留痕：append-only JSONL + SHA-256 哈希链，可离线验证

## 快速开始

```bash
python examples/demo.py                       # 脚本走查
python -m unittest discover -s tests -t . -v  # 23 tests，零第三方依赖
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

## 规则是数据，不是代码

见 `rules/rules.example.json`（`RuleSet.from_json` 加载）：

```json
{
  "red_lines": [
    {"id": "DEMO-RL-001", "description": "outbound of restricted data",
     "action_types": ["outbound"], "data_classes": ["restricted"]}
  ],
  "fence": {"per_call": 500.0, "per_day": 2000.0, "per_month": 5000.0}
}
```

## 传输层

`protocol.py` 只实现**语义层**（`audit.call` / `audit.resolve` / `audit.pending`，
stdio JSON 行）。绑定 MCP、A2A 或 HTTP 属于传输层，留给调用方——因此同一套规则引擎
可在本地、沙箱或网关后运行，无需改动。

## 状态与边界

- 状态：**参考实现**，非加固产品，无 SLA
- 非目标：不执行工具调用、不存 payload、不替代你的 IAM、不替你定业务规则——规则由你写
- 生产使用前请自行做安全审查

## 贡献 / 安全 / 许可

- 贡献见 [CONTRIBUTING.md](../CONTRIBUTING.md)（fail-closed 优先、零新依赖、去标识提交、测试全绿）
- 安全问题见 [SECURITY.md](../SECURITY.md)
- 许可 MIT，见 `LICENSE`

## 联系方式

**福瑞通 · 数字工作台（Furitong Digital Workspace）**——自动化工作台，AI 辅助交付。
业务咨询：**2307788504@qq.com**。不提供投资建议、法律意见，不接加密货币相关工作。

---
*Copyright (c) 2026 福瑞通 · 数字工作台。MIT 许可。*