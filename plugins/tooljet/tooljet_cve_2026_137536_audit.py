#!/usr/bin/env python3
"""
RTMS Audit Plugin — ToolJet OAuth SSO Sign-In Bypass & Release Workflow Command Injection Audit
Target CVEs:
  - CVE-2026-137536 (CVSS 9.3, Critical): ToolJet before 3.21.94-beta contains an authentication
    bypass in its server OAuth SSO sign-in module, resolving Google and Git SSO logins solely by
    provider-asserted email without checking email_verified or binding the SSO subject.
  - CVE-2026-137964 (CVSS 9.3, Critical): ToolJet before 3.21.96-LTS contains a command injection
    vulnerability in its release workflow prior to 3.21.96-LTS.

Strictly read-only passive version check via ToolJet health/config endpoints or supplied version string.
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


TOOLJET_CVES: List[str] = ["CVE-2026-137536", "CVE-2026-137964"]


def parse_tooljet_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a ToolJet version string (e.g. '3.21.93', '3.21.96-LTS', 'v3.21.96') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)(?:-[a-z0-9.]+)?\b", text.strip(), re.IGNORECASE)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_tooljet_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-137536 (< 3.21.94-beta) and CVE-2026-137964 (< 3.21.96-LTS)."""
    if version < (3, 21, 96):
        return True, "3.21.96-LTS"
    return False, "3.21.96-LTS"


class ToolJetAuditPlugin(BasePlugin):
    name = "tooljet_cve_2026_137536_audit"
    description = (
        "Passive version check for ToolJet OAuth SSO authentication bypass and release compliance "
        "(CVE-2026-137536, CVE-2026-137964, CVSS 9.3)"
    )
    author = "RTMS Security Team"
    version = "1.1.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "tooljet_cve_2026_137536_audit",
            "description": (
                "Passive version check for ToolJet OAuth SSO authentication bypass and release compliance "
                "(CVE-2026-137536, CVE-2026-137964, CVSS 9.3)"
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-137536, CVE-2026-137964",
            "version": "1.1.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 8082))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/api/metadata", "/api/config", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "tooljet" not in body.lower() and path == "/":
                continue
            parsed = parse_tooljet_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("tooljet_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied tooljet_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(TOOLJET_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine ToolJet version.",
                "remediation": "Upgrade ToolJet to version 3.21.96-LTS or later.",
                "evidence": evidence,
            }

        parsed = parse_tooljet_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(TOOLJET_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized ToolJet version format: '{raw_version}'.",
                "remediation": "Upgrade ToolJet to version 3.21.96-LTS or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_tooljet_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            matched_cves = ["CVE-2026-137964"]
            if parsed < (3, 21, 94):
                matched_cves.insert(0, "CVE-2026-137536")
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": matched_cves,
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"ToolJet {ver_display} is vulnerable to {', '.join(matched_cves)} "
                    f"(fixed in {fixed})."
                ),
                "remediation": f"Upgrade ToolJet to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(TOOLJET_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"ToolJet {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ToolJet CVE-2026-137536 / CVE-2026-137964 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="tooljet_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"tooljet_version": args.tooljet_version} if args.tooljet_version else {}
    print(ToolJetAuditPlugin(args.target, opts).run_audit())
