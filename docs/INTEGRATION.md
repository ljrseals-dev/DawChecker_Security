# Integrating DawChecker Security

## Minimal integration

```python
from dawchecker_security import SecurityEngine, ActionContext, Decision

engine = SecurityEngine()  # local defaults, no network

def before_tool_call(tool_name: str, arguments: dict) -> None:
    ctx = ActionContext(
        action_type="mcp",
        tool_name=tool_name,
        arguments=arguments,
        agent="my-harness",
    )
    result = engine.evaluate(ctx)
    if result.decision == Decision.BLOCK:
        raise PermissionError(result.reason)
    if result.decision == Decision.ASK:
        # Present to user, then optionally:
        # engine.remember(ctx, Decision.ALLOW, reason="user approved")
        raise PermissionError(f"Approval required: {result.reason}")
```

## Shell wrapper

```python
import subprocess
from dawchecker_security import SecurityEngine, ActionContext, Decision

engine = SecurityEngine()

def safe_run(cmd: str) -> subprocess.CompletedProcess:
    ctx = ActionContext(action_type="shell", command=cmd)
    result = engine.evaluate(ctx)
    if result.decision != Decision.ALLOW:
        raise PermissionError(result.reason)
    return subprocess.run(cmd, shell=True, check=True)
```

## Custom policy

Copy `config/default_policy.yaml`, edit rules, then:

```python
engine = SecurityEngine(policy_path="path/to/my_policy.yaml")
```

## Data locations

| Data              | Default location                                      |
|-------------------|-------------------------------------------------------|
| Receipts          | `~/.local/share/dawchecker-security/receipts/`        |
| Approvals         | `~/.config/dawchecker-security/approvals/`            |
| Integrity key     | `~/.config/dawchecker-security/approvals/.integrity_key` |

Override with the `data_dir` / `receipt_dir` / `approval_dir` constructor arguments or CLI `--data-dir`.

## No commercial surfaces

There is no:

- Account or sign-in
- Cloud connect / sync
- License or subscription check
- Feature flag that disables protection
- Telemetry or phone-home

Everything required for baseline protection runs offline.