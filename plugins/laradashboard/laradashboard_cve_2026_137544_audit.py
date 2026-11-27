#!/usr/bin/env python3
"""
RTMS Audit Plugin — LaraDashboard Module Namespace Path Traversal & RCE Audit
Target CVE:
  - CVE-2026-137544 (CVSS 9.4, Critical): LaraDashboard before 1.5.0 contains a path traversal
    vulnerability in module.json providers and composer.json psr-4 namespace parsing.

Strictly read-only passive version check via public page metadata or supplied version string.
"""

import argparse
import re
import ssl
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

try:
    from core.plugin_base import BasePlugin
except ImportError:

    class BasePlugin:
        def __init__(self, target: str, options: Optional[Dict] = None):
            self.target = target
            self.options = options or {}


def parse_laradashboard_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a LaraDashboard version string (e.g. '1.4.2', '1.5.0') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_laradashboard_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-137544 (< 1.5.0)."""
    if version < (1, 5, 0):
        return True, "1.5.0"
    return False, "1.5.0"


class LaraDashboardAuditPlugin(BasePlugin):
    name = "laradashboard_cve_2026_137544_audit"
    description = (
        "Passive version check for LaraDashboard module namespace path traversal "
        "(CVE-2026-137544, CVSS 9.4)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "laradashboard_cve_2026_137544_audit",
            "description": "Passive version check for LaraDashboard module namespace path traversal (CVE-2026-137544, CVSS 9.4)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-137544",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 443))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", True) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/", "/login"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "laradashboard" not in body.lower():
                continue
            parsed = parse_laradashboard_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("laradashboard_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied laradashboard_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137544"],
                "severity": "INFO",
                "finding": "Could not passively determine LaraDashboard version.",
                "remediation": "Upgrade LaraDashboard to version 1.5.0 or later.",
                "evidence": evidence,
            }

        parsed = parse_laradashboard_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137544"],
                "severity": "INFO",
                "finding": f"Unrecognized LaraDashboard version format: '{raw_version}'.",
                "remediation": "Upgrade LaraDashboard to version 1.5.0 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_laradashboard_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137544"],
                "severity": "CRITICAL",
                "cvss": 9.4,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"LaraDashboard {ver_display} is vulnerable to CVE-2026-137544 "
                    f"(path traversal in module.json and composer.json parsing, fixed in {fixed})."
                ),
                "remediation": f"Upgrade LaraDashboard to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137544"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"LaraDashboard {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LaraDashboard CVE-2026-137544 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="laradashboard_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"laradashboard_version": args.laradashboard_version} if args.laradashboard_version else {}
    print(LaraDashboardAuditPlugin(args.target, opts).run_audit())
