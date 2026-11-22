"""
MCP (Model Context Protocol) tool-call classifier.

Reviews tool names and argument shapes for path traversal, secret access,
arbitrary code execution, and DAW/audio resource manipulation.
"""

from __future__ import annotations

from typing import Any, Optional

from dawchecker_security.classifiers.base import Classification


HIGH_RISK_TOOLS = {
    "bash": 0.7,
    "shell": 0.7,
    "run_terminal_cmd": 0.7,
    "execute": 0.75,
    "eval": 0.9,
    "write_file": 0.5,
    "delete_file": 0.65,
    "remove": 0.65,
    "http_request": 0.55,
    "fetch": 0.5,
    "browser": 0.45,
    "computer": 0.8,
}

DAW_MCP_TOOLS = {
    "load_plugin",
    "scan_clap",
    "render_audio",
    "export_stems",
    "set_tempo",
    "add_track",
    "insert_fx",
    "bounce",
    "freeze_track",
}


class McpClassifier:
    def classify(
        self,
        tool_name: str,
        arguments: Optional[dict[str, Any]] = None,
    ) -> Classification:
        if not tool_name:
            return Classification(labels=["empty_tool"], risk=0.0)

        name = tool_name.strip().lower()
        args = arguments or {}
        labels: list[str] = []
        risk = 0.1
        reasons: list[str] = []

        for tool, score in HIGH_RISK_TOOLS.items():
            if tool in name:
                labels.append(f"high_risk_tool:{tool}")
                risk = max(risk, score)
                reasons.append(f"Tool name contains high-risk token: {tool}")

        if name in DAW_MCP_TOOLS or any(t in name for t in DAW_MCP_TOOLS):
            labels.append("daw_mcp_tool")
            risk = max(risk, 0.3)
            reasons.append("DAW-related MCP tool")

        # Argument inspection
        for key, value in args.items():
            key_l = str(key).lower()
            val_s = str(value).lower() if value is not None else ""

            if any(s in key_l for s in ("path", "file", "dir", "folder")):
                if ".." in val_s or val_s.startswith("/etc") or val_s.startswith("/home"):
                    labels.append("path_traversal_or_sensitive")
                    risk = max(risk, 0.8)
                    reasons.append(f"Suspicious path argument: {key}={value}")

            if any(s in key_l for s in ("cmd", "command", "script", "code", "expr")):
                labels.append("code_execution_arg")
                risk = max(risk, 0.85)
                reasons.append(f"Code/command argument present: {key}")

            if any(s in key_l for s in ("key", "token", "secret", "password", "credential")):
                labels.append("secret_argument")
                risk = max(risk, 0.9)
                reasons.append(f"Secret-like argument: {key}")

        if not labels:
            labels.append("ordinary_mcp")

        return Classification(
            labels=sorted(set(labels)),
            risk=min(risk, 1.0),
            reason="; ".join(reasons) if reasons else None,
        )