"""
Core security engine.

Evaluates an ActionContext against local policy, classifiers, and remembered
decisions. Returns a Decision (allow / block / ask) and optionally records a
receipt. Everything runs on the local machine; no network calls are required
for baseline protection.
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

from dawchecker_security.classifiers.shell import ShellClassifier
from dawchecker_security.classifiers.file_access import FileAccessClassifier
from dawchecker_security.classifiers.package import PackageClassifier
from dawchecker_security.classifiers.mcp import McpClassifier
from dawchecker_security.classifiers.daw import DawSurfaceClassifier
from dawchecker_security.policy.engine import PolicyEngine, PolicyDecision
from dawchecker_security.receipts.store import ReceiptStore, Receipt
from dawchecker_security.approvals.memory import ApprovalMemory


class Decision(enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


@dataclass
class ActionContext:
    """Everything known about an action before it runs."""

    action_type: str  # shell | file | package | mcp | plugin | daw
    command: Optional[str] = None
    path: Optional[str] = None
    package: Optional[str] = None
    tool_name: Optional[str] = None
    arguments: dict[str, Any] = field(default_factory=dict)
    agent: Optional[str] = None
    session_id: Optional[str] = None
    cwd: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash used for remembered decisions."""
        payload = {
            "action_type": self.action_type,
            "command": self.command,
            "path": self.path,
            "package": self.package,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "agent": self.agent,
            "session_id": self.session_id,
            "cwd": self.cwd,
        }
        raw = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass
class EvaluationResult:
    decision: Decision
    reason: str
    risk_score: float  # 0.0 – 1.0
    classifications: list[str] = field(default_factory=list)
    receipt_id: Optional[str] = None
    policy_rule: Optional[str] = None
    requires_human: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d


class SecurityEngine:
    """
    Local-first security engine.

    - Loads policy from local YAML/JSON (no remote fetch).
    - Classifies actions with pure-Python rules.
    - Honours remembered local approvals (integrity-checked).
    - Writes receipts to a local store.
    - Never phones home. Never requires a cloud account.
    """

    def __init__(
        self,
        policy_path: Optional[Path | str] = None,
        receipt_dir: Optional[Path | str] = None,
        approval_dir: Optional[Path | str] = None,
        auto_record: bool = True,
    ) -> None:
        self.policy = PolicyEngine(policy_path)
        self.receipts = ReceiptStore(receipt_dir)
        self.approvals = ApprovalMemory(approval_dir)
        self.auto_record = auto_record

        self.shell = ShellClassifier()
        self.file_access = FileAccessClassifier()
        self.package = PackageClassifier()
        self.mcp = McpClassifier()
        self.daw = DawSurfaceClassifier()

    def evaluate(self, ctx: ActionContext) -> EvaluationResult:
        """Evaluate an action and return a decision."""
        classifications: list[str] = []
        risk = 0.0
        reasons: list[str] = []

        # 1. Classifier suite
        if ctx.action_type == "shell" and ctx.command:
            c = self.shell.classify(ctx.command, cwd=ctx.cwd)
            classifications.extend(c.labels)
            risk = max(risk, c.risk)
            if c.reason:
                reasons.append(c.reason)

        if ctx.action_type in ("file", "shell") and ctx.path:
            c = self.file_access.classify(ctx.path, action=ctx.extra.get("op", "read"))
            classifications.extend(c.labels)
            risk = max(risk, c.risk)
            if c.reason:
                reasons.append(c.reason)

        if ctx.action_type == "package" and ctx.package:
            c = self.package.classify(ctx.package, manager=ctx.extra.get("manager", "pip"))
            classifications.extend(c.labels)
            risk = max(risk, c.risk)
            if c.reason:
                reasons.append(c.reason)

        if ctx.action_type == "mcp" and ctx.tool_name:
            c = self.mcp.classify(ctx.tool_name, arguments=ctx.arguments)
            classifications.extend(c.labels)
            risk = max(risk, c.risk)
            if c.reason:
                reasons.append(c.reason)

        if ctx.action_type in ("daw", "plugin", "mcp"):
            c = self.daw.classify(ctx)
            classifications.extend(c.labels)
            risk = max(risk, c.risk)
            if c.reason:
                reasons.append(c.reason)

        # 3. Policy evaluation
        policy_result: PolicyDecision = self.policy.evaluate(
            action_type=ctx.action_type,
            classifications=classifications,
            risk_score=risk,
            context=ctx,
        )

        decision = Decision(policy_result.decision)
        reason = policy_result.reason or ("; ".join(reasons) if reasons else "No elevated risk detected)

        # 3. Remembered decisions are consulted only after current classifiers/policy.
        remembered = self.approvals.lookup(ctx.fingerprint())
        if isinstance(remembered, dict):
            remembered_decision = remembered.get("decision")
            if remembered_decision in (Decision.ALLOW.value, Decision.BLOCK.value):
                if decision == Decision.BLOCK:
                    # Current policy hard blocks always win.
                    pass
                elif remembered_decision == Decision.BLOCK.value:
                    decision = Decision.BLOCK
                    reason = f"Remembered local block: {remembered.get('reason', 'prior denial')}"
                elif decision == Decision.ASK:
                    decision = Decision.ALLOW
                    reason = f"Remembered local decision: {remembered.get('reason', 'prior approval')}"
                    policy_result.rule_id = "remembered-approval"

        requires_human = decision == Decision.ASK

        result = EvaluationResult(
            decision=decision,
            reason=reason,
            risk_score=round(risk, 3),
            classifications=sorted(set(classifications)),
            policy_rule=policy_result.rule_id,
            requires_human=requires_human,
        )

        # 4. Optional receipt
        if self.auto_record:
            receipt = self.receipts.record(
                Receipt(
                    id=str(uuid.uuid4()),
                    timestamp=time.time(),
                    action_type=ctx.action_type,
                    fingerprint=ctx.fingerprint(),
                    decision=decision.value,
                    reason=reason,
                    risk_score=result.risk_score,
                    classifications=result.classifications,
                    agent=ctx.agent,
                    session_id=ctx.session_id,
                    context_snapshot={
                        "command": ctx.command,
                        "path": ctx.path,
                        "package": ctx.package,
                        "tool_name": ctx.tool_name,
                    },
                )
            )
            result.receipt_id = receipt.id

        return result

    def remember(
        self,
        ctx: ActionContext,
        decision: Decision,
        reason: str = "User decision",
        risk_score: float = 0.0,
        classifications: Optional[list[str]] = None,
    ) -> None:
        """Store a local remembered decision (integrity-protected)."""
        self.approvals.store(
            fingerprint=ctx.fingerprint(),
            decision=decision.value,
            reason=reason,
            risk_score=risk_score,
            classifications=classifications or [],
        )

    def status(self) -> dict[str, Any]:
        """Local status — no network."""
        return {
            "version": "1.0.0",
            "mode": "local-first",
            "cloud": False,
            "paywall": False,
            "subscription": False,
            "policy_loaded": self.policy.is_loaded(),
            "receipt_count": self.receipts.count(),
            "remembered_decisions": self.approvals.count(),
            "classifiers": ["shell", "file_access", "package", "mcp", "daw"],
        }