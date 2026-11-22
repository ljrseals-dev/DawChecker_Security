"""
DAW / audio surface classifier.

Specialised checks for CLAP/VST plugin paths, audio render commands,
MCP music tools, and project-file manipulation that are relevant to
DawChecker and related local audio pipelines.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dawchecker_security.classifiers.base import Classification

if TYPE_CHECKING:
    from dawchecker_security.core import ActionContext


class DawSurfaceClassifier:
    def classify(self, ctx: "ActionContext") -> Classification:
        labels: list[str] = []
        risk = 0.0
        reasons: list[str] = []

        # Plugin path indicators
        path = (ctx.path or "").lower()
        cmd = (ctx.command or "").lower()
        tool = (ctx.tool_name or "").lower()

        plugin_markers = (".vst3", ".clap", ".component", ".dll", ".so", "plugins/", "vst/", "clap/")
        if any(m in path for m in plugin_markers) or any(m in cmd for m in plugin_markers):
            labels.append("plugin_surface")
            risk = max(risk, 0.4)
            reasons.append("Plugin binary or directory referenced")

        # Destructive audio operations
        if any(x in cmd for x in ("rm -rf", "delete_track", "clear_session", "wipe")):
            labels.append("destructive_daw_op")
            risk = max(risk, 0.75)
            reasons.append("Destructive DAW operation pattern")

        # Remote sample / preset fetch
        if any(x in cmd for x in ("http://", "https://", "ftp://")) and any(
            x in cmd for x in ("sample", "preset", "wav", "aiff", "flac", "mid")
        ):
            labels.append("remote_audio_asset")
            risk = max(risk, 0.55)
            reasons.append("Remote audio asset fetch")

        # MCP music tools already partially covered; reinforce here
        if ctx.action_type in ("mcp", "daw") and any(
            t in tool for t in ("render", "bounce", "export", "scan_clap", "load_plugin")
        ):
            labels.append("daw_render_or_scan")
            risk = max(risk, 0.35)
            reasons.append("DAW render / plugin scan tool")

        # Project file write
        project_exts = (".als", ".flp", ".cpr", ".logicx", ".dawproject", ".rpp")
        if any(path.endswith(ext) for ext in project_exts) and ctx.extra.get("op") in (
            "write",
            "overwrite",
            "delete",
        ):
            labels.append("project_file_mutation")
            risk = max(risk, 0.6)
            reasons.append("Mutation of DAW project file")

        if not labels:
            labels.append("ordinary_daw")
            risk = 0.05

        return Classification(
            labels=sorted(set(labels)),
            risk=min(risk, 1.0),
            reason="; ".join(reasons) if reasons else None,
        )