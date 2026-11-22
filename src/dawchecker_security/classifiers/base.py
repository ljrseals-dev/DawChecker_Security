"""Shared classification result type."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Classification:
    labels: list[str] = field(default_factory=list)
    risk: float = 0.0  # 0.0 (safe) – 1.0 (critical)
    reason: Optional[str] = None

    def merge(self, other: "Classification") -> "Classification":
        return Classification(
            labels=sorted(set(self.labels + other.labels)),
            risk=max(self.risk, other.risk),
            reason="; ".join(filter(None, [self.reason, other.reason])) or None,
        )