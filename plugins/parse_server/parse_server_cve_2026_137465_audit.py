#!/usr/bin/env python3
"""
RTMS Audit Plugin — Parse Server Google Play Games Authentication Bypass Audit
Target CVE:
  - CVE-2026-137465 (CVSS 9.1, Critical): Parse Server 3.10.0 before 8.6.123 and 9.0.0 before
    9.11.1-alpha.4 does not verify that the supplied player ID belongs to the presented access token
    in the Google Play Games authentication adapter.

Strictly read-only passive version check via server info / package metadata or supplied version string.
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


def parse_parse_server_version(text: str) -> Optional[Tuple[int, int, int, int]]:
    """
    Parse a Parse Server version string (e.g. '8.6.122', '8.6.123', '9.11.1-alpha.3', '9.11.1-alpha.4')
    into (major, minor, patch, alpha_num) where regular release has alpha_num=9999.
    """
    if not text:
        return None
    m = re.search(r"\b(\d+)\.(\d+)\.(\d+)(?:-alpha\.(\d+))?\b", text.strip(), re.IGNORECASE)
    if not m:
        return None
    alpha = int(m.group(4)) if m.group(4) is not None else 9999
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), alpha)


def is_parse_server_version_vulnerable(version: Tuple[int, int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-137465.
    Affected:
      - 3.10.0 <= v < 8.6.123
      - 9.0.0 <= v < 9.11.1-alpha.4
    """
    major = version[0]
    if 3 <= major <= 8:
        if (3, 10, 0, 0) <= version < (8, 6, 123, 0):
            return True, "8.6.123"
        return False, "8.6.123"
    if major == 9:
        if (9, 0, 0, 0) <= version < (9, 11, 1, 4):
            return True, "9.11.1-alpha.4"
        return False, "9.11.1-alpha.4"
    return False, "8.6.123 / 9.11.1-alpha.4"


class ParseServerAuditPlugin(BasePlugin):
    name = "parse_server_cve_2026_137465_audit"
    description = (
        "Passive version check for Parse Server Google Play Games authentication bypass "
        "(CVE-2026-137465, CVSS 9.1)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "parse_server_cve_2026_137465_audit",
            "description": "Passive version check for Parse Server Google Play Games authentication bypass (CVE-2026-137465, CVSS 9.1)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-137465",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 1337))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/parse/serverInfo", "/health", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "parse" not in body.lower():
                continue
            parsed = parse_parse_server_version(body)
            if parsed:
                ver_str = (
                    f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                    if parsed[3] == 9999
                    else f"{parsed[0]}.{parsed[1]}.{parsed[2]}-alpha.{parsed[3]}"
                )
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("parse_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied parse_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137465"],
                "severity": "INFO",
                "finding": "Could not passively determine Parse Server version.",
                "remediation": "Upgrade Parse Server to 8.6.123+ or 9.11.1-alpha.4+.",
                "evidence": evidence,
            }

        parsed = parse_parse_server_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137465"],
                "severity": "INFO",
                "finding": f"Unrecognized Parse Server version format: '{raw_version}'.",
                "remediation": "Upgrade Parse Server to 8.6.123+ or 9.11.1-alpha.4+.",
                "evidence": evidence,
            }

        vuln, fixed = is_parse_server_version_vulnerable(parsed)
        ver_display = (
            f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
            if parsed[3] == 9999
            else f"{parsed[0]}.{parsed[1]}.{parsed[2]}-alpha.{parsed[3]}"
        )
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137465"],
                "severity": "CRITICAL",
                "cvss": 9.1,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Parse Server {ver_display} is vulnerable to CVE-2026-137465 "
                    f"(Google Play Games adapter authentication bypass, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Parse Server to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137465"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Parse Server {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse Server CVE-2026-137465 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="parse_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"parse_version": args.parse_version} if args.parse_version else {}
    print(ParseServerAuditPlugin(args.target, opts).run_audit())
