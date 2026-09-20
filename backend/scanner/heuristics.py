"""
Lightweight Supply Chain Name Heuristics: Typosquatting & Dependency Confusion.

Performs static lexical analysis of package names without code execution.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from typing import Any, Dict, List, Optional, Set

try:
    from rapidfuzz import fuzz, distance
except ImportError:
    fuzz = None
    distance = None

logger = logging.getLogger("supplyguard.scanner.heuristics")

# Configurable popular trusted packages across npm and PyPI
DEFAULT_TRUSTED_PACKAGES: Set[str] = {
    "react",
    "express",
    "lodash",
    "axios",
    "chalk",
    "commander",
    "mongoose",
    "next",
    "webpack",
    "vite",
    "requests",
    "flask",
    "django",
}

# Configurable internal/private naming patterns for dependency confusion
DEFAULT_INTERNAL_PATTERNS: List[str] = [
    "company-*",
    "internal-*",
    "private-*",
    "@company/*",
    "@internal/*",
    "*-internal",
    "corp-*",
]


def _levenshtein(s1: str, s2: str) -> int:
    """Pure Python fallback Levenshtein distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def detect_typosquatting(
    package_name: str,
    trusted_packages: Optional[Set[str]] = None,
    threshold: float = 82.0,
) -> Optional[Dict[str, Any]]:
    """
    Detect if package_name is an apparent typosquat of a trusted package.

    Detects:
    - insertion (expreess vs express)
    - deletion (expres vs express)
    - substitution (reqeusts vs requests)
    - transposition (exrpress vs express)
    - repeated characters (expresss vs express)
    """
    trusted_set = trusted_packages or DEFAULT_TRUSTED_PACKAGES
    clean_name = package_name.strip().lower()

    # Exact match is the real trusted package, NOT a typosquat
    if clean_name in trusted_set:
        return None

    for trusted in sorted(trusted_set):
        # Quick length filter: typos typically within 1-2 chars difference
        if abs(len(clean_name) - len(trusted)) > 2:
            continue

        ratio = 0.0
        dist = 999

        if fuzz is not None and distance is not None:
            ratio = float(fuzz.ratio(clean_name, trusted))
            dist = int(distance.Levenshtein.distance(clean_name, trusted))
        else:
            dist = _levenshtein(clean_name, trusted)
            ratio = max(0.0, 100.0 - (dist / max(len(clean_name), len(trusted)) * 100.0))

        # A candidate typosquat has high similarity and edit distance 1 or 2
        if dist in (1, 2) and ratio >= threshold:
            confidence = round(min(0.95, max(0.70, ratio / 100.0)), 2)
            return {
                "trusted_target": trusted,
                "similarity": ratio,
                "distance": dist,
                "confidence": confidence,
                "evidence": f"Package '{package_name}' is suspiciously close to popular package '{trusted}' (edit distance {dist}, similarity {ratio:.0f}%).",
            }

    return None


def detect_dependency_confusion(
    package_name: str,
    internal_patterns: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Detect if a package uses private/internal naming patterns that pose
    dependency confusion or namespace takeover risks.
    """
    patterns = internal_patterns or DEFAULT_INTERNAL_PATTERNS
    clean_name = package_name.strip().lower()

    for pat in patterns:
        if fnmatch.fnmatch(clean_name, pat.lower()):
            return {
                "matched_pattern": pat,
                "confidence": 0.85,
                "evidence": f"Package name '{package_name}' matches internal naming pattern '{pat}' susceptible to public dependency confusion.",
            }

    return None


class SupplyChainHeuristicsScanner:
    """
    Analyzes dependency names for typosquatting and dependency confusion.
    """

    def __init__(
        self,
        trusted_packages: Optional[Set[str]] = None,
        internal_patterns: Optional[List[str]] = None,
    ) -> None:
        self.trusted_packages = trusted_packages or DEFAULT_TRUSTED_PACKAGES
        self.internal_patterns = internal_patterns or DEFAULT_INTERNAL_PATTERNS

    def scan(
        self,
        dependencies: List[Dict[str, Any]],
        blast_radii: Optional[Dict[str, float]] = None,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        radii = blast_radii or {}
        seen_packages: Set[str] = set()

        for dep in dependencies:
            pkg = (dep.get("package_name") or dep.get("package") or "").strip()
            if not pkg or pkg.lower() in seen_packages:
                continue
            seen_packages.add(pkg.lower())

            eco = dep.get("ecosystem") or "unknown"
            version = dep.get("version") or "*"
            direct = bool(dep.get("direct", dep.get("dependency_type") != "transitive"))
            depth = int(dep.get("depth", 0))
            blast = radii.get(pkg.lower(), 0.50)

            # 1. Typosquatting Check
            typo_res = detect_typosquatting(pkg, self.trusted_packages)
            if typo_res:
                target = typo_res["trusted_target"]
                findings.append({
                    "finding_id": f"F-TYPO-{pkg.lower()}",
                    "type": "typosquatting",
                    "package": pkg,
                    "ecosystem": eco,
                    "version": version,
                    "severity": "HIGH",
                    "confidence": typo_res["confidence"],
                    "source": ["typosquatting_detector"],
                    "summary": f"Potential typosquatting of '{target}'",
                    "evidence": [
                        {
                            "rule": "TYPOSQUATTING",
                            "trusted_package": target,
                            "distance": typo_res["distance"],
                            "similarity": typo_res["similarity"],
                            "details": typo_res["evidence"],
                        }
                    ],
                    "remediation": {
                        "advice": f"Verify package identity before use. Did you mean to install '{target}'?",
                        "recommended_package": target,
                    },
                    "direct": direct,
                    "depth": depth,
                    "blast_radius": blast,
                })

            # 2. Dependency Confusion Check
            conf_res = detect_dependency_confusion(pkg, self.internal_patterns)
            if conf_res:
                pattern = conf_res["matched_pattern"]
                findings.append({
                    "finding_id": f"F-CONFUSION-{pkg.lower()}",
                    "type": "dependency_confusion",
                    "package": pkg,
                    "ecosystem": eco,
                    "version": version,
                    "severity": "HIGH",
                    "confidence": conf_res["confidence"],
                    "source": ["dependency_confusion_detector"],
                    "summary": f"Matches internal namespace pattern '{pattern}'",
                    "evidence": [
                        {
                            "rule": "DEPENDENCY_CONFUSION",
                            "pattern": pattern,
                            "details": conf_res["evidence"],
                        }
                    ],
                    "remediation": {
                        "advice": "Verify package is registered in private enterprise repository and not pulled from public registry.",
                    },
                    "direct": direct,
                    "depth": depth,
                    "blast_radius": blast,
                })

        return findings
