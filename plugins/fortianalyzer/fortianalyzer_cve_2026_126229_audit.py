#!/usr/bin/env python3
"""
RTMS Audit Plugin — Fortinet FortiAnalyzer Authorization Bypass Through User-Controlled Key
Target CVE:
  - CVE-2026-126229 (CVSS 9.1, Critical): Authorization bypass through user-controlled key
    (CWE-639) in Fortinet FortiAnalyzer allowing an attacker to access restricted analytics,
    log repositories, and administrative endpoints.

Affected versions:
  - FortiAnalyzer 7.2.0 <= version <= 7.2.12 (patched in 7.2.13)
  - FortiAnalyzer 7.4.0 <= version <= 7.4.11 (patched in 7.4.12)
  - FortiAnalyzer 7.6.0 <= version <= 7.6.7 (patched in 7.6.8)
  - FortiAnalyzer 8.0.0 <= version <= 8.0.1 (patched in 8.0.2)

Strictly read-only passive version check via management portal metadata or supplied firmware
version. No unauthorized API calls or parameter tampering are performed.
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


def parse_fortianalyzer_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a FortiAnalyzer firmware version string (e.g. 'v7.6.7-build3401', '7.4.11', '8.0.1')
    into a (major, minor, patch) tuple.
    """
    if not version_str:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_fortianalyzer_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-126229.
    """
    major, minor, patch = version
    if (major, minor) == (7, 2) and 0 <= patch <= 12:
        return True, "7.2.13"
    if (major, minor) == (7, 4) and 0 <= patch <= 11:
        return True, "7.4.12"
    if (major, minor) == (7, 6) and 0 <= patch <= 7:
        return True, "7.6.8"
    if (major, minor) == (8, 0) and 0 <= patch <= 1:
        return True, "8.0.2"
    return False, "8.0.2"


class FortiAnalyzerAuditPlugin(BasePlugin):
    name = "fortianalyzer_cve_2026_126229_audit"
    description = (
        "Passive version check for Fortinet FortiAnalyzer authorization bypass "
        "(CVE-2026-126229, CVSS 9.1)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "fortianalyzer_cve_2026_126229_audit",
            "description": "Passive version check for Fortinet FortiAnalyzer authorization bypass (CVE-2026-126229, CVSS 9.1)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-126229",
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
        if ":" in t:
            return f"{scheme}://{t}"
        return f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        patterns = [
            re.compile(r"FortiAnalyzer[^0-9]{0,25}v?([78]\.[0246]\.[0-9]+)", re.IGNORECASE),
            re.compile(r'"version"\s*:\s*"v?([78]\.[0246]\.[0-9]+)"', re.IGNORECASE),
        ]

        for path in ("/p/login/", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "RTMS-Compliance-Audit/1.0"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                try:
                    body = e.read(65536).decode("utf-8", errors="ignore")
                except Exception:
                    body = ""
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            for pat in patterns:
                m = pat.search(body)
                if m:
                    ver = m.group(1)
                    evidence.append(f"Version extracted from {path}: {ver}")
                    return ver, evidence

        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("fortianalyzer_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied fortianalyzer_version option: {raw_version}")
        else:
            base_url = self._build_base_url()
            raw_version, probe_ev = self._probe_version(base_url, timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-126229"],
                "severity": "INFO",
                "finding": "Could not passively determine Fortinet FortiAnalyzer version.",
                "remediation": (
                    "Check FortiAnalyzer firmware via `get system status` and upgrade to "
                    "7.2.13, 7.4.12, 7.6.8, or 8.0.2+."
                ),
                "evidence": evidence,
            }

        parsed = parse_fortianalyzer_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-126229"],
                "severity": "INFO",
                "finding": f"Unrecognized FortiAnalyzer version format: '{raw_version}'.",
                "remediation": "Upgrade FortiAnalyzer to 7.2.13, 7.4.12, 7.6.8, or 8.0.2+.",
                "evidence": evidence,
            }

        vuln, fixed = is_fortianalyzer_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"

        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-126229"],
                "severity": "CRITICAL",
                "cvss": 9.1,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Fortinet FortiAnalyzer {ver_display} is vulnerable to CVE-2026-126229 "
                    f"(authorization bypass through user-controlled key, fixed in {fixed})."
                ),
                "remediation": f"Upgrade FortiAnalyzer firmware to {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-126229"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Fortinet FortiAnalyzer {ver_display} is not within an affected firmware range.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FortiAnalyzer CVE-2026-126229 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="fortianalyzer_version", help="Override detected version string")
    args = parser.parse_args()

    opts = {}
    if args.fortianalyzer_version:
        opts["fortianalyzer_version"] = args.fortianalyzer_version
    plugin = FortiAnalyzerAuditPlugin(args.target, opts)
    print(plugin.run_audit())
