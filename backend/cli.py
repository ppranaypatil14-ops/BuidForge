"""
DepScan AI CLI — Standalone Terminal Scanner, SBOM Exporter, and CI/CD Quality Gate.

Usage:
    python -m backend.cli ./demo-repository
    python -m backend.cli ./demo-repository --sbom sbom.cdx.json --sarif results.sarif
    python -m backend.cli ./demo-repository --gate
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from backend.ingestion.workspace import RepositoryWorkspace
from backend.models.domain import Repository
from backend.models.enums import ScanStatus
from backend.pipeline import run_scan


# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"


def colorize(text: str, color: str, enable_color: bool = True) -> str:
    if not enable_color:
        return text
    return f"{color}{text}{RESET}"


def export_cyclonedx_sbom(result: Dict[str, Any], output_path: Path) -> None:
    """Generate and write CycloneDX v1.5 JSON SBOM."""
    dependencies = result.get("dependencies", [])
    findings = result.get("findings", [])
    scan_id = result.get("scan_id", str(uuid.uuid4()))

    components = []
    for dep in dependencies:
        pkg = dep.get("package", "unknown")
        ver = dep.get("version", "unknown").lstrip("^~=<>")
        eco = dep.get("ecosystem", "generic")
        purl = f"pkg:{eco}/{pkg}@{ver}" if ver != "unknown" else f"pkg:{eco}/{pkg}"
        components.append(
            {
                "type": "library",
                "name": pkg,
                "version": ver,
                "purl": purl,
                "properties": [
                    {"name": "depscan:ecosystem", "value": str(eco)},
                    {"name": "depscan:is_direct", "value": str(dep.get("is_direct", True))},
                    {"name": "depscan:manifest_path", "value": str(dep.get("manifest_path", ""))},
                ],
            }
        )

    vulnerabilities = []
    for f in findings:
        pkg = f.get("package", "unknown")
        ver = f.get("version", "unknown").lstrip("^~=<>")
        eco = f.get("ecosystem", "generic")
        purl = f"pkg:{eco}/{pkg}@{ver}" if ver != "unknown" else f"pkg:{eco}/{pkg}"
        vulnerabilities.append(
            {
                "id": f.get("id") or f.get("rule_id", "VULN-001"),
                "source": {"name": "DepScan AI Risk Engine"},
                "ratings": [
                    {
                        "severity": str(f.get("severity", "medium")).lower(),
                        "method": "CVSSv3",
                    }
                ],
                "description": f.get("title", "Supply chain security finding"),
                "recommendation": f.get("remediation", {}).get("advice", ""),
                "affects": [{"ref": purl}],
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "DepScan AI",
                    "name": "SupplyGuard",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": Path(result.get("repository", {}).get("url", "workspace")).stem or "target-repo",
                "version": "1.0.0",
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)


def export_sarif_report(result: Dict[str, Any], output_path: Path) -> None:
    """Generate and write SARIF v2.1.0 JSON report."""
    findings = result.get("findings", [])

    rules = []
    sarif_results = []
    seen_rules = set()

    for idx, f in enumerate(findings):
        rule_id = f.get("rule_id") or f"RULE-{idx + 1}"
        sev = str(f.get("severity", "MEDIUM")).upper()
        level = "error" if sev in ("CRITICAL", "HIGH") else ("warning" if sev == "MEDIUM" else "note")

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": f.get("finding_type", "SecurityFinding"),
                    "shortDescription": {"text": f.get("title", rule_id)},
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "priority": f.get("priority", "P2"),
                        "severity": sev,
                    },
                }
            )

        manifest = f.get("manifest_path") or "package.json"
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{f.get('title', 'Security Finding')} (Package: {f.get('package', 'unknown')})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": manifest,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
                "properties": {
                    "package": f.get("package"),
                    "version": f.get("version"),
                    "remediation": f.get("remediation", {}).get("advice", ""),
                },
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DepScan AI",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/Atharvchaskar008/Kurukshetra-hackathon",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)


def render_terminal_table(result: Dict[str, Any], enable_color: bool = True) -> None:
    """Print an ANSI summary table of scan results."""
    status = result.get("status", "unknown").upper()
    score = result.get("score", 0.0)
    risk_level = result.get("risk_level", "SAFE").upper()
    ecosystems = ", ".join(result.get("ecosystems", [])) or "None detected"
    dependencies = result.get("dependencies", [])
    findings = result.get("findings", [])

    risk_color = RED if risk_level in ("CRITICAL", "HIGH") else (YELLOW if risk_level == "MEDIUM" else GREEN)

    print()
    print(colorize("=" * 80, CYAN, enable_color))
    print(colorize(f" 🛡️  DEPSCAN AI — SUPPLY CHAIN SECURITY REPORT", BOLD + WHITE, enable_color))
    print(colorize("=" * 80, CYAN, enable_color))
    print(f" Target:         {colorize(str(result.get('repository', {}).get('url', 'workspace')), BOLD, enable_color)}")
    print(f" Scan ID:        {result.get('scan_id')}")
    print(f" Status:         {colorize(status, GREEN if status == 'COMPLETED' else YELLOW, enable_color)}")
    print(f" Ecosystems:     {colorize(ecosystems, CYAN, enable_color)}")
    print(f" Dependencies:   {len(dependencies)}")
    print(f" Security Score: {colorize(f'{score:.1f} / 100.0', BOLD, enable_color)}")
    print(f" Overall Risk:   {colorize(f'[{risk_level}]', risk_color + BOLD, enable_color)}")
    print(colorize("-" * 80, CYAN, enable_color))

    if not findings:
        print(colorize("\n ✨ Clean scan! No security attack vectors or vulnerable dependencies detected.\n", GREEN + BOLD, enable_color))
        print(colorize("=" * 80, CYAN, enable_color))
        return

    print(f"\n {colorize(f'FINDINGS SUMMARY ({len(findings)} detected)', BOLD + WHITE, enable_color)}:\n")

    # Table header
    header_fmt = "{:<6} {:<10} {:<24} {:<40}"
    print(colorize(header_fmt.format("PRIO", "SEVERITY", "PACKAGE", "SUMMARY"), BOLD, enable_color))
    print(colorize("-" * 84, DIM, enable_color))

    for f in findings:
        prio = f.get("priority", "P3")
        sev = str(f.get("severity", "LOW")).upper()
        pkg = f.get("package", "unknown")
        ver = f.get("version", "")
        pkg_display = f"{pkg}@{ver}" if ver else pkg
        title = f.get("title", "Finding")[:38]

        # Severity & Priority color
        if prio == "P0" or sev == "CRITICAL":
            sev_color = RED + BOLD
        elif prio == "P1" or sev == "HIGH":
            sev_color = YELLOW + BOLD
        elif prio == "P2" or sev == "MEDIUM":
            sev_color = YELLOW
        else:
            sev_color = CYAN

        line = header_fmt.format(prio, sev, pkg_display[:22], title)
        print(colorize(line, sev_color, enable_color))

    print(colorize("-" * 84, DIM, enable_color))

    # Breakdown by severity
    crit_count = sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH")
    med_count = sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM")
    low_count = sum(1 for f in findings if str(f.get("severity")).upper() == "LOW")

    print(f"\n Severity Breakdown: "
          f"{colorize(f'{crit_count} Critical', RED + BOLD, enable_color)} | "
          f"{colorize(f'{high_count} High', YELLOW + BOLD, enable_color)} | "
          f"{colorize(f'{med_count} Medium', YELLOW, enable_color)} | "
          f"{colorize(f'{low_count} Low', CYAN, enable_color)}")
    print(colorize("=" * 80, CYAN, enable_color))
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="depscan",
        description="DepScan AI — Software Supply Chain Security Analyzer CLI",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to repository or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--sbom",
        metavar="PATH",
        type=str,
        help="Export CycloneDX v1.5 JSON SBOM to specified file path",
    )
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        type=str,
        help="Export SARIF v2.1.0 report to specified file path",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="Enforce CI/CD Quality Gate (exits with code 1 on P0/Critical findings, 0 on clean)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON scan results to stdout",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output",
    )

    args = parser.parse_args()
    enable_color = not args.no_color and sys.stdout.isatty()

    target_path = Path(args.target).resolve()
    if not target_path.exists() or not target_path.is_dir():
        print(f"Error: Target directory does not exist: {target_path}", file=sys.stderr)
        sys.exit(2)

    workspace = RepositoryWorkspace(workspace_dir=target_path, auto_cleanup=False)
    scan_id = f"cli_{uuid.uuid4().hex[:12]}"
    files = workspace.list_files()

    repo_metadata = Repository(
        url=str(target_path),
        name=target_path.name,
        file_count=len(files),
        metadata={"source": "cli"},
    )

    result = run_scan(scan_id, workspace, repo_metadata)

    if args.json:
        print(json.dumps(result, indent=2))

    if not args.json:
        render_terminal_table(result, enable_color=enable_color)

    if args.sbom:
        sbom_path = Path(args.sbom).resolve()
        export_cyclonedx_sbom(result, sbom_path)
        print(f"📦 CycloneDX SBOM exported successfully to: {sbom_path}")

    if args.sarif:
        sarif_path = Path(args.sarif).resolve()
        export_sarif_report(result, sarif_path)
        print(f"📋 SARIF report exported successfully to: {sarif_path}")

    if args.gate:
        findings = result.get("findings", [])
        blocking_findings = [
            f for f in findings
            if f.get("priority") == "P0" or str(f.get("severity", "")).upper() == "CRITICAL"
        ]

        if blocking_findings:
            msg = (
                f"❌ CI/CD QUALITY GATE FAILED: {len(blocking_findings)} blocking (P0 / Critical) "
                f"finding(s) identified in {target_path.name}."
            )
            print(colorize(f"\n{msg}\n", BG_RED + WHITE + BOLD, enable_color))
            sys.exit(1)
        else:
            msg = f"✅ CI/CD QUALITY GATE PASSED: 0 blocking findings detected in {target_path.name}."
            print(colorize(f"\n{msg}\n", BG_GREEN + WHITE + BOLD, enable_color))
            sys.exit(0)


if __name__ == "__main__":
    main()
