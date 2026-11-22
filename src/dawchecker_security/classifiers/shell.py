"""
Shell command classifier.

Detects destructive operations, credential exposure, network exfiltration
patterns, privilege escalation, and suspicious piping. Pure local rules.
"""

from __future__ import annotations

import re
from typing import Optional

from dawchecker_security.classifiers.base import Classification


# High-risk patterns (ordered roughly by severity)
DESTRUCTIVE = [
    (r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(/|~|\.\.)", "destructive_delete", 0.95),
    (r"\brm\s+-rf\b", "destructive_delete", 0.98),
    (r"\bmkfs\b|\bdd\s+if=", "disk_wipe", 0.99),
    (r">\s*/dev/sd[a-z]", "disk_overwrite", 0.99),
    (r"\bchmod\s+777\b|\bchmod\s+-R\s+777\b", "overly_permissive", 0.7),
]

CREDENTIAL = [
    (r"\b(cat|less|more|head|tail)\s+.*(\.env|credentials|id_rsa|id_ed25519|\.aws/|\.ssh/)", "secret_read", 0.9),
    (r"\becho\s+.*\$\{?(AWS|GITHUB|OPENAI|ANTHROPIC|HF)_", "secret_echo", 0.85),
    (r"\bprintenv\b|\benv\b.*\|", "env_dump", 0.6),
    (r"\bhistory\b.*\|.*grep", "history_snoop", 0.55),
]

NETWORK = [
    (r"\bcurl\b.*\|\s*(ba)?sh\b", "pipe_to_shell", 0.95),
    (r"\bwget\b.*\|\s*(ba)?sh\b", "pipe_to_shell", 0.95),
    (r"\bcurl\b.*(-d|--data).*api[_-]?key", "exfil_key", 0.9),
    (r"\bnc\s+-l|\bncat\s+-l|\bpython\s+-m\s+http\.server", "listener", 0.7),
    (r"\bscp\b|\brsync\b.*@", "remote_copy", 0.65),
]

PRIVILEGE = [
    (r"\bsudo\b|\bdoas\b", "privilege_escalation", 0.75),
    (r"\bsu\s+-", "privilege_escalation", 0.8),
    (r"\bchown\s+root\b|\bchmod\s+[gu]\+s\b", "setuid_or_root", 0.85),
]

PACKAGE_INSTALL = [
    (r"\bpip\s+install\b|\bpip3\s+install\b", "package_install", 0.4),
    (r"\bnpm\s+install\b|\byarn\s+add\b|\bpnpm\s+add\b", "package_install", 0.4),
    (r"\bapt(-get)?\s+install\b|\byum\s+install\b|\bdnf\s+install\b", "system_package", 0.55),
    (r"\bbrew\s+install\b", "package_install", 0.35),
]

DAW_AUDIO = [
    (r"\bfmpeg\b.*-i\s+.*(http|ftp)", "remote_audio_fetch", 0.5),
    (r"\bsox\b|\baubio\b|\blibrosa\b", "audio_tool", 0.2),
    (r"\bjackd\b|\bpulseaudio\b|\bpipewire\b", "audio_server", 0.3),
]


class ShellClassifier:
    def classify(self, command: str, cwd: Optional[str] = None) -> Classification:
        if not command or not command.strip():
            return Classification(labels=["empty"], risk=0.0)

        cmd = command.strip()
        labels: list[str] = []
        risk = 0.0
        reasons: list[str] = []

        for pattern, label, score in (
            DESTRUCTIVE + CREDENTIAL + NETWORK + PRIVILEGE + PACKAGE_INSTALL + DAW_AUDIO
        ):
            if re.search(pattern, cmd, re.IGNORECASE):
                labels.append(label)
                if score > risk:
                    risk = score
                    reasons.append(f"Matched {label}")

        # Heuristic: very long one-liners with base64 or eval
        if len(cmd) > 400 and ("base64" in cmd.lower() or "eval" in cmd.lower()):
            labels.append("obfuscated_long")
            risk = max(risk, 0.8)
            reasons.append("Long command with base64/eval")

        if not labels:
            labels.append("benign")
            risk = 0.05

        return Classification(
            labels=sorted(set(labels)),
            risk=min(risk, 1.0),
            reason="; ".join(reasons) if reasons else None,
        )