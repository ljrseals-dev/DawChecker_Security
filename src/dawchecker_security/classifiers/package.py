"""
Package install classifier.

Flags known-typo-squatting patterns, unpinned installs from untrusted indexes,
and packages that historically appear in supply-chain incidents.
Local heuristics only — no live vulnerability database required.
"""

from __future__ import annotations

from typing import Optional

from dawchecker_security.classifiers.base import Classification


# Small curated set of high-signal names / patterns (illustrative, not exhaustive)
SUSPICIOUS_NAMES = {
    "python-dateutil-utils",  # common typo-squat style
    "reqeusts",
    "urllib3-secure",
    "pip-install",
    "setup-tools",
    "colourama",
    "beautifulsoup4-utils",
}

HIGH_IMPACT_PACKAGES = {
    "cryptography",
    "pycrypto",
    "paramiko",
    "fabric",
    "ansible",
    "docker",
    "kubernetes",
    "openai",
    "anthropic",
    "transformers",
    "torch",
}


class PackageClassifier:
    def classify(self, package: str, manager: str = "pip") -> Classification:
        if not package:
            return Classification(labels=["empty_package"], risk=0.0)

        name = package.strip().split("==")[0].split(">=")[0].split("<=")[0].strip().lower()
        labels: list[str] = []
        risk = 0.15  # any install carries baseline risk
        reasons: list[str] = []

        if name in SUSPICIOUS_NAMES:
            labels.append("typosquat_suspect")
            risk = 0.9
            reasons.append(f"Name matches known suspicious pattern: {name}")

        if name in HIGH_IMPACT_PACKAGES:
            labels.append("high_impact_package")
            risk = max(risk, 0.45)
            reasons.append(f"High-impact package: {name}")

        # Unpinned version
        if "==" not in package and ">=" not in package and "~=" not in package:
            labels.append("unpinned")
            risk = max(risk, 0.35)
            reasons.append("Unpinned package version")

        # Extra index / private index indicators
        if "extra-index-url" in package.lower() or "find-links" in package.lower():
            labels.append("extra_index")
            risk = max(risk, 0.55)
            reasons.append("Extra package index referenced")

        if manager in ("npm", "yarn", "pnpm") and name.startswith("@"):
            labels.append("scoped_package")
            risk = max(risk, 0.25)

        if not labels:
            labels.append("ordinary_package")

        return Classification(
            labels=sorted(set(labels)),
            risk=min(risk, 1.0),
            reason="; ".join(reasons) if reasons else None,
        )