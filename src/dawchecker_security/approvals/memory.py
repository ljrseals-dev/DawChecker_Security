"""
Local approval memory.

Stores remembered allow/block decisions keyed by action fingerprint.
A simple HMAC-style integrity tag (using a local key file) prevents
trivial silent tampering of the on-disk store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Optional


def _default_approval_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "dawchecker-security" / "approvals"


class ApprovalMemory:
    def __init__(self, root: Optional[Path | str] = None) -> None:
        self.root = Path(root) if root else _default_approval_dir()
        self.root.mkdir(parents=True, exist_ok=True)
        self._store = self.root / "decisions.json"
        self._key_file = self.root / ".integrity_key"
        self._key = self._load_or_create_key()
        self._data: dict[str, Any] = self._load()

    def _load_or_create_key(self) -> bytes:
        if self._key_file.exists():
            return self._key_file.read_bytes()
        key = secrets.token_bytes(32)
        self._key_file.write_bytes(key)
        try:
            self._key_file.chmod(0o600)
        except OSError:
            pass
        return key

    def _tag(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _load(self) -> dict[str, Any]:
        if not self._store.exists():
            return {}
        raw = self._store.read_bytes()
        try:
            outer = json.loads(raw.decode("utf-8"))
            body = outer.get("body", {})
            tag = outer.get("tag", "")
            expected = self._tag(json.dumps(body, sort_keys=True).encode("utf-8"))
            if not hmac.compare_digest(tag, expected):
                # Integrity failure — treat as empty rather than trusting
                return {}
            return body
        except (json.JSONDecodeError, KeyError, TypeError):
            return {}

    def _save(self) -> None:
        body = self._data
        tag = self._tag(json.dumps(body, sort_keys=True).encode("utf-8"))
        outer = {"body": body, "tag": tag, "updated": time.time()}
        self._store.write_text(json.dumps(outer, indent=2), encoding="utf-8")
        try:
            self._store.chmod(0o600)
        except OSError:
            pass

    def lookup(self, fingerprint: str) -> Optional[dict[str, Any]]:
        return self._data.get(fingerprint)

    def store(
        self,
        fingerprint: str,
        decision: str,
        reason: str = "",
        risk_score: float = 0.0,
        classifications: Optional[list[str]] = None,
    ) -> None:
        self._data[fingerprint] = {
            "decision": decision,
            "reason": reason,
            "risk_score": risk_score,
            "classifications": classifications or [],
            "stored_at": time.time(),
        }
        self._save()

    def forget(self, fingerprint: str) -> bool:
        if fingerprint in self._data:
            del self._data[fingerprint]
            self._save()
            return True
        return False

    def count(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        self._data = {}
        self._save()