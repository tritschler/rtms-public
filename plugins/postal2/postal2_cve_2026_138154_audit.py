#!/usr/bin/env python3
"""
RTMS Audit Plugin — POSTAL 2 Workshop Mod Sandbox Escape Build Compliance Audit
Target CVE:
  - CVE-2026-138154 (CVSS 9.3, Critical): POSTAL 2 before build 26810491 contains a sandbox
    escape vulnerability allowing Workshop mods to execute arbitrary code via ConsoleCommand.

Strictly read-only passive build number compliance check.
"""

import argparse
import re
from typing import Dict, List, Optional, Tuple

try:
    from core.plugin_base import BasePlugin
except ImportError:

    class BasePlugin:
        def __init__(self, target: str, options: Optional[Dict] = None):
            self.target = target
            self.options = options or {}


def parse_postal2_build(text: str) -> Optional[int]:
    """Parse a POSTAL 2 build identifier (e.g. '26810490', 'build 26810491') into an integer build number."""
    if not text:
        return None
    m = re.search(r"\b(\d{6,10})\b", text.strip())
    if not m:
        return None
    return int(m.group(1))


def is_postal2_build_vulnerable(build: int) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_build) for CVE-2026-138154 (< 26810491)."""
    if build < 26810491:
        return True, "26810491"
    return False, "26810491"


class Postal2AuditPlugin(BasePlugin):
    name = "postal2_cve_2026_138154_audit"
    description = (
        "Passive build compliance check for POSTAL 2 Workshop mod sandbox escape "
        "(CVE-2026-138154, CVSS 9.3)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "postal2_cve_2026_138154_audit",
            "description": (
                "Passive build compliance check for POSTAL 2 Workshop mod sandbox escape "
                "(CVE-2026-138154, CVSS 9.3)"
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-138154",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        raw_build = self.options.get("build_version")
        evidence: List[str] = []

        if raw_build:
            evidence.append(f"Using supplied build_version option: {raw_build}")
        else:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-138154"],
                "severity": "INFO",
                "finding": "No POSTAL 2 build number supplied for passive verification.",
                "remediation": "Update POSTAL 2 to Steam build 26810491 or later.",
                "evidence": evidence,
            }

        parsed = parse_postal2_build(str(raw_build))
        if parsed is None:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-138154"],
                "severity": "INFO",
                "finding": f"Unrecognized POSTAL 2 build format: '{raw_build}'.",
                "remediation": "Update POSTAL 2 to Steam build 26810491 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_postal2_build_vulnerable(parsed)
        ver_display = str(parsed)
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-138154"],
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"POSTAL 2 build {ver_display} is vulnerable to CVE-2026-138154 "
                    f"(Workshop mod sandbox escape, fixed in build {fixed})."
                ),
                "remediation": f"Update POSTAL 2 to build {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-138154"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"POSTAL 2 build {ver_display} is at or above patched build {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="POSTAL 2 CVE-2026-138154 Passive Build Audit")
    parser.add_argument("--target", required=True, help="Target host or asset identifier")
    parser.add_argument("--version", dest="build_version", help="Build number (e.g. 26810491)")
    args = parser.parse_args()
    opts = {"build_version": args.build_version} if args.build_version else {}
    print(Postal2AuditPlugin(args.target, opts).run_audit())
