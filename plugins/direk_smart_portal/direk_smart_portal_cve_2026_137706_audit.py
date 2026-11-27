#!/usr/bin/env python3
"""
RTMS Audit Plugin — Direk Tech Smart Portal Missing Authorization Audit
Target CVE:
  - CVE-2026-137706 (CVSS 9.4, Critical): Missing Authorization vulnerability in Direk Tech
    Smart Portal allowing authenticated remote attackers to add an account to Active Directory Domain Admins.

Strictly read-only passive version check via public portal metadata or supplied version string.
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


def parse_smart_portal_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Direk Tech Smart Portal version string (e.g. '2.4.0', '2026.11.0', '2026.12.0') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_smart_portal_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-137706.
    All releases prior to the 2026.12.0 patch build are affected.
    """
    if version < (2026, 12, 0):
        return True, "2026.12.0"
    return False, "2026.12.0"


class DirekSmartPortalAuditPlugin(BasePlugin):
    name = "direk_smart_portal_cve_2026_137706_audit"
    description = (
        "Passive version check for Direk Tech Smart Portal missing authorization "
        "(CVE-2026-137706, CVSS 9.4)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

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

            if "smart portal" not in body.lower() and "direk" not in body.lower():
                continue
            parsed = parse_smart_portal_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("portal_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied portal_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137706"],
                "severity": "INFO",
                "finding": "Could not passively determine Direk Tech Smart Portal version.",
                "remediation": "Apply the vendor security patch (>= 2026.12.0) and restrict portal access.",
                "evidence": evidence,
            }

        parsed = parse_smart_portal_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137706"],
                "severity": "INFO",
                "finding": f"Unrecognized Direk Tech Smart Portal version format: '{raw_version}'.",
                "remediation": "Apply the vendor security patch (>= 2026.12.0).",
                "evidence": evidence,
            }

        vuln, fixed = is_smart_portal_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137706"],
                "severity": "CRITICAL",
                "cvss": 9.4,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Direk Tech Smart Portal {ver_display} is vulnerable to CVE-2026-137706 "
                    f"(missing authorization on AD Domain Admins group modification)."
                ),
                "remediation": f"Upgrade Direk Tech Smart Portal to {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137706"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Direk Tech Smart Portal {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Direk Tech Smart Portal CVE-2026-137706 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="portal_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"portal_version": args.portal_version} if args.portal_version else {}
    print(DirekSmartPortalAuditPlugin(args.target, opts).run_audit())
