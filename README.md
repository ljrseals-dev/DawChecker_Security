# DawChecker Security

**Local-first runtime security for AI agents and DAW tooling.**

No cloud account. No paywalls. No subscriptions. No telemetry.

Policy-based review of shell commands, file access, package installs, MCP tool calls, and DAW/plugin surfaces. Decisions are **allow**, **block**, or **ask**. Every decision can produce a durable local receipt. Remembered approvals stay on your machine and are integrity-protected.

This package extracts the useful *local* security patterns (classification, policy, receipts, approval memory) and ships them as a clean, complete, self-contained library ready to integrate with DawChecker and related audio / agent pipelines.

---

## Principles

| Principle              | Status                          |
|------------------------|---------------------------------|
| Local-first            | Always                          |
| Cloud required         | Never                           |
| Paywall / subscription | None                            |
| Telemetry              | None                            |
| Network for baseline   | Not required                    |
| License                | Apache-2.0                      |

---

## Install

```bash
pip install -e .
# or
pipx install .
```

Requires Python 3.10+.

---

## Quick start

```bash
# Status (proves local-only mode)
dawchecker-sec status

# Evaluate a shell command
dawchecker-sec evaluate shell -c "rm -rf /tmp/foo"

# Evaluate a package install
dawchecker-sec evaluate package --package "requests"

# Evaluate an MCP tool call
dawchecker-sec evaluate mcp --tool write_file --args '{"path":"/etc/passwd"}'

# Show recent receipts
dawchecker-sec receipts

# Remember an allow decision
dawchecker-sec remember shell -c "echo hello" --decision allow
```

Python API:

```python
from dawchecker_security import SecurityEngine, ActionContext, Decision

engine = SecurityEngine()

ctx = ActionContext(action_type="shell", command="rm -rf /")
result = engine.evaluate(ctx)

if result.decision == Decision.BLOCK:
    raise PermissionError(result.reason)
```

---

## What is reviewed

| Surface        | Examples                                      |
|----------------|-----------------------------------------------|
| Shell          | Destructive commands, pipe-to-shell, secrets  |
| File access    | SSH keys, `.env`, system paths, DAW projects  |
| Packages       | Unpinned installs, typo-squat names           |
| MCP tools      | Code-execution args, path traversal, secrets  |
| DAW / plugins  | Project mutation, plugin paths, remote assets |

---

## Policy

Default policy lives in `config/default_policy.yaml`.  
Copy it, edit the rules, and pass `--policy path/to/policy.yaml`.

Rules are evaluated in order; first match wins.  
Supported match keys: `action_type`, `classifications_any`, `classifications_all`, `risk_above`, `risk_below`.

---

## Integration with DawChecker

1. Add this package as a dependency of your DawChecker / harness project.
2. Instantiate `SecurityEngine` once at startup (optionally with a custom policy path).
3. Before any side-effecting tool call, build an `ActionContext` and call `engine.evaluate(ctx)`.
4. Honour `BLOCK` and surface `ASK` to the user; call `engine.remember(...)` when the user decides.
5. Receipts and approval memory stay under `~/.local/share/dawchecker-security` and `~/.config/dawchecker-security` (or your `data-dir`).

Decorator helper:

```python
from dawchecker_security.harness import review_before
from dawchecker_security import SecurityEngine

engine = SecurityEngine()

@review_before(engine, action_type="shell", command_arg="cmd")
def run_shell(cmd: str) -> str:
    ...
```

---

## Design notes (vs. commercial gate models)

- **No cloud pairing** – there is no `connect`, `sync`, or account step.
- **No feature flags that disable protection** – baseline review always runs.
- **No subscription checks** – the library never inspects a license or plan.
- **Integrity of remembered decisions** – local HMAC key protects the approval store from casual tampering.
- **Complete code** – every module is fully implemented; there are no stubs or placeholder tails.

Ideas and patterns drawn from the open-source local runtime of [hashgraph-online/hol-guard](https://github.com/hashgraph-online/hol-guard) (Apache-2.0). All commercial / cloud / subscription surfaces have been removed.

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check src tests
```

---

## License

Apache-2.0. See `LICENSE`.

Copyright 2026 ljrseals-dev.  
Incorporates patterns from hol-guard under the same license; commercial gates removed.