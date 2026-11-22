"""
Local receipt store.

Append-only JSONL file under the user's config directory.
No remote upload. No telemetry.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Iterator, Optional


def _default_receipt_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / "dawchecker-security" / "receipts"


@dataclass
class Receipt:
    id: str
    timestamp: float
    action_type: str
    fingerprint: str
    decision: str
    reason: str
    risk_score: float
    classifications: list[str] = field(default_factory=list)
    agent: Optional[str] = None
    session_id: Optional[str] = None
    context_snapshot: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReceiptStore:
    def __init__(self, root: Optional[Path | str] = None) -> None:
        self.root = Path(root) if root else _default_receipt_dir()
        self.root.mkdir(parents=True, exist_ok=True)
        self._file = self.root / "receipts.jsonl"

    def record(self, receipt: Receipt) -> Receipt:
        line = json.dumps(receipt.to_dict(), default=str) + "\n"
        with open(self._file, "a", encoding="utf-8") as f:
            f.write(line)
        return receipt

    def count(self) -> int:
        if not self._file.exists():
            return 0
        with open(self._file, "r", encoding="utf-8") as f:
            return sum(1 for _ in f)

    def iter_recent(self, limit: int = 50) -> Iterator[Receipt]:
        if not self._file.exists():
            return
        lines: list[str] = []
        with open(self._file, "r", encoding="utf-8") as f:
            for line in f:
                lines.append(line)
        for line in lines[-limit:]:
            data = json.loads(line)
            yield Receipt(**data)

    def clear(self) -> None:
        if self._file.exists():
            self._file.unlink()