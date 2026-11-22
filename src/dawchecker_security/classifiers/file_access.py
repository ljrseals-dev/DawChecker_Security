"""
File access classifier.

Flags sensitive paths (secrets, keys, system config, DAW project data)
and high-impact operations (write/delete on critical locations).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dawchecker_security.classifiers.base import Classification


SENSITIVE_PATH_FRAGMENTS = [
    (".ssh/", "ssh_key_dir", 0.95),
    ("id_rsa", "private_key", 0.98),
    ("id_ed25519", "private_key", 0.98),
    (".aws/credentials", "aws_credentials", 0.95),
    (".env", "dotenv", 0.85),
    ("credentials.json", "credentials_file", 0.9),
    ("secrets.yaml", "secrets_file", 0.9),
    ("secrets.yml", "secrets_file", 0.9),
    ("/etc/passwd", "system_passwd", 0.7),
    ("/etc/shadow", "system_shadow", 0.99),
    (".gnupg/", "gpg_dir", 0.9),
    ("Library/Keychains", "macos_keychain", 0.9),
    ("AppData/Roaming", "windows_roaming", 0.4),
]

DAW_SENSITIVE = [
    (".als", "ableton_project", 0.3),  # Ableton
    (".flp", "flstudio_project", 0.3),
    (".cpr", "cubase_project", 0.3),
    (".logicx", "logic_project", 0.3),
    (".band", "garageband", 0.25),
    ("Plugins/", "plugin_dir", 0.35),
    ("VST3/", "vst3_dir", 0.4),
    ("CLAP/", "clap_dir", 0.4),
    (".dawproject", "dawproject", 0.3),
]


class FileAccessClassifier:
    def classify(self, path: str, action: str = "read") -> Classification:
        if not path:
            return Classification(labels=["empty_path"], risk=0.0)

        p = path.replace("\\", "/")
        labels: list[str] = []
        risk = 0.0
        reasons: list[str] = []

        lower = p.lower()

        for frag, label, score in SENSITIVE_PATH_FRAGMENTS:
            if frag.lower() in lower:
                labels.append(label)
                if score > risk:
                    risk = score
                    reasons.append(f"Sensitive path fragment: {frag}")

        for frag, label, score in DAW_SENSITIVE:
            if frag.lower() in lower:
                labels.append(label)
                if score > risk:
                    risk = score
                    reasons.append(f"DAW-related path: {frag}")

        # Write / delete on sensitive locations raises risk
        if action in ("write", "delete", "overwrite", "unlink") and risk > 0.3:
            risk = min(1.0, risk + 0.25)
            labels.append(f"{action}_on_sensitive")
            reasons.append(f"Write/delete on sensitive location")

        # Absolute system paths
        if p.startswith("/etc/") or p.startswith("/usr/") or p.startswith("/System/"):
            labels.append("system_path")
            risk = max(risk, 0.55)
            reasons.append("System path access")

        if not labels:
            labels.append("ordinary_path")
            risk = 0.05

        return Classification(
            labels=sorted(set(labels)),
            risk=min(risk, 1.0),
            reason="; ".join(reasons) if reasons else None,
        )