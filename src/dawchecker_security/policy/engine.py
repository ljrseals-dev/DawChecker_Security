"""
Local policy engine.

Loads a YAML/JSON policy file from disk. No remote policy fetch.
Rules are evaluated in order; first match wins.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


DEFAULT_POLICY = {
    "version": 1,
    "default": "ask",
    "rules": [
        {
            "id": "block-destructive",
            "match": {"classifications_any": ["destructive_delete", "disk_wipe", "disk_overwrite"]},
            "decision": "block",
            "reason": "Destructive filesystem operation blocked by policy",
        },
        {
            "id": "block-secret-exfil",
            "match": {"classifications_any": ["secret_read", "secret_echo", "exfil_key", "secret_argument"]},
            "decision": "block",
            "reason": "Potential secret exposure or exfiltration blocked",
        },
        {
            "id": "block-pipe-to-shell",
            "match": {"classifications_any": ["pipe_to_shell"]},
            "decision": "block",
            "reason": "Remote content piped to shell is blocked",
        },
        {
            "id": "ask-privilege",
            "match": {"classifications_any": ["privilege_escalation", "setuid_or_root"]},
            "decision": "ask",
            "reason": "Privilege escalation requires explicit approval",
        },
        {
            "id": "ask-high-risk-mcp",
            "match": {"classifications_any": ["code_execution_arg", "path_traversal_or_sensitive"]},
            "decision": "ask",
            "reason": "High-risk MCP arguments require approval",
        },
        {
            "id": "ask-project-mutation",
            "match": {"classifications_any": ["project_file_mutation", "destructive_daw_op"]},
            "decision": "ask",
            "reason": "DAW project mutation requires approval",
        },
        {
            "id": "ask-unpinned-or-suspect",
            "match": {"classifications_any": ["typosquat_suspect", "unpinned", "extra_index"]},
            "decision": "ask",
            "reason": "Package install risk requires review",
        },
        {
            "id": "allow-low-risk",
            "match": {"risk_below": 0.25},
            "decision": "allow",
            "reason": "Low risk score — allowed by policy",
        },
    ],
}


@dataclass
class PolicyDecision:
    decision: str  # allow | block | ask
    reason: str
    rule_id: Optional[str] = None


class PolicyEngine:
    def __init__(self, policy_path: Optional[Path | str] = None) -> None:
        self._path = Path(policy_path) if policy_path else None
        self._policy: dict[str, Any] = dict(DEFAULT_POLICY)
        self._loaded = False
        if self._path and self._path.exists():
            self.load(self._path)

    def is_loaded(self) -> bool:
        return self._loaded or self._path is None

    def load(self, path: Path | str) -> None:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            if yaml is None:
                raise RuntimeError("PyYAML is required for YAML policy files")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        if not isinstance(data, dict) or "rules" not in data:
            raise ValueError("Policy must be a dict containing a 'rules' list")
        self._policy = data
        self._loaded = True
        self._path = p

    def evaluate(
        self,
        action_type: str,
        classifications: list[str],
        risk_score: float,
        context: Any = None,
    ) -> PolicyDecision:
        rules = self._policy.get("rules", [])
        default = self._policy.get("default", "ask")

        for rule in rules:
            match = rule.get("match", {})
            if self._matches(match, action_type, classifications, risk_score):
                return PolicyDecision(
                    decision=rule.get("decision", default),
                    reason=rule.get("reason", f"Matched rule {rule.get('id')}"),
                    rule_id=rule.get("id"),
                )

        return PolicyDecision(
            decision=default,
            reason="No rule matched — using policy default",
            rule_id=None,
        )

    def _matches(
        self,
        match: dict[str, Any],
        action_type: str,
        classifications: list[str],
        risk_score: float,
    ) -> bool:
        if "action_type" in match and match["action_type"] != action_type:
            return False
        if "classifications_any" in match:
            needed = set(match["classifications_any"])
            if not needed.intersection(classifications):
                return False
        if "classifications_all" in match:
            needed = set(match["classifications_all"])
            if not needed.issubset(classifications):
                return False
        if "risk_above" in match and risk_score <= float(match["risk_above"]):
            return False
        if "risk_below" in match and risk_score >= float(match["risk_below"]):
            return False
        return True