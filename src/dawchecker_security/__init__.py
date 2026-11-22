"""
DawChecker Security — Local-first runtime security for AI agents and DAW tooling.

No cloud account required. No paywalls. No subscriptions.
Policy-based allow / block / approve with durable receipts.
"""

__version__ = "1.0.0"
__license__ = "Apache-2.0"

from dawchecker_security.core import SecurityEngine, Decision, ActionContext
from dawchecker_security.policy.engine import PolicyEngine, PolicyDecision
from dawchecker_security.receipts.store import ReceiptStore, Receipt

__all__ = [
    "SecurityEngine",
    "Decision",
    "ActionContext",
    "PolicyEngine",
    "PolicyDecision",
    "ReceiptStore",
    "Receipt",
    "__version__",
]