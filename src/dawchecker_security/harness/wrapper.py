"""
Simple integration helpers.

Use review_before() as a decorator or call GuardedCallable around any
function that performs a side-effecting action you want reviewed.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional

from dawchecker_security.core import SecurityEngine, ActionContext, Decision, EvaluationResult


def review_before(
    engine: SecurityEngine,
    action_type: str = "shell",
    command_arg: str = "command",
    path_arg: Optional[str] = None,
    on_block: str = "raise",  # raise | return_none | return_result
):
    """
    Decorator that evaluates an ActionContext built from function kwargs
    before the wrapped function runs.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            command = kwargs.get(command_arg)
            path = kwargs.get(path_arg) if path_arg else None
            ctx = ActionContext(
                action_type=action_type,
                command=command if isinstance(command, str) else None,
                path=path if isinstance(path, str) else None,
                extra={"kwargs_keys": list(kwargs.keys())},
            )
            result = engine.evaluate(ctx)
            if result.decision == Decision.BLOCK:
                if on_block == "raise":
                    raise PermissionError(f"Blocked by DawChecker Security: {result.reason}")
                if on_block == "return_none":
                    return None
                return result
            if result.decision == Decision.ASK:
                # In interactive settings the caller should present the result
                # and optionally call engine.remember(). Here we treat ASK as block
                # unless the caller has already remembered an allow.
                if on_block == "raise":
                    raise PermissionError(
                        f"Approval required by DawChecker Security: {result.reason}"
                    )
                if on_block == "return_none":
                    return None
                return result
            return fn(*args, **kwargs)

        return wrapper

    return decorator


class GuardedCallable:
    """
    Wrap any callable so that a pre-built ActionContext is evaluated
    before each invocation.
    """

    def __init__(
        self,
        engine: SecurityEngine,
        ctx: ActionContext,
        fn: Callable[..., Any],
        on_block: str = "raise",
    ) -> None:
        self.engine = engine
        self.ctx = ctx
        self.fn = fn
        self.on_block = on_block

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        result: EvaluationResult = self.engine.evaluate(self.ctx)
        if result.decision in (Decision.BLOCK, Decision.ASK):
            if self.on_block == "raise":
                raise PermissionError(f"{result.decision.value}: {result.reason}")
            if self.on_block == "return_none":
                return None
            return result
        return self.fn(*args, **kwargs)