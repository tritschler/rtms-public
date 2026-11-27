#!/usr/bin/env python3
"""
RTMS Audit Plugin — Frappe Framework Document.update() Missing Authorization Audit
Target CVE:
  - CVE-2026-137550 (CVSS 9.3, Critical): Frappe Framework before 15.122.0 and 16.x before 16.50.0
    contains a missing authorization vulnerability in Document.update() that fails to validate whether
    the caller is permitted to submit or modify the target document.

Strictly read-only passive version check via Frappe version metadata or supplied version string.
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


def parse_frappe_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Frappe Framework version string (e.g. '15.121.0', '16.49.0', 'v15.122.0') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_frappe_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-137550.
    Affected:
      - < 15.122.0
      - 16.x < 16.50.0
    """
    major = version[0]
    if major <= 15:
        return (version < (15, 122, 0), "15.122.0")
    if major == 16:
        return (version < (16, 50, 0), "16.50.0")
    return False, "15.122.0 / 16.50.0"


class FrappeAuditPlugin(BasePlugin):
    name = "frappe_cve_2026_137550_audit"
    description = (
        "Passive version check for Frappe Framework Document.update() missing authorization "
        "(CVE-2026-137550, CVSS 9.3)"
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

        for path in ("/api/method/frappe.utils.change_log.get_versions", "/login", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "frappe" not in body.lower():
                continue
            parsed = parse_frappe_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("frappe_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied frappe_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137550"],
                "severity": "INFO",
                "finding": "Could not passively determine Frappe Framework version.",
                "remediation": "Upgrade Frappe Framework to 15.122.0+ or 16.50.0+.",
                "evidence": evidence,
            }

        parsed = parse_frappe_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137550"],
                "severity": "INFO",
                "finding": f"Unrecognized Frappe Framework version format: '{raw_version}'.",
                "remediation": "Upgrade Frappe Framework to 15.122.0+ or 16.50.0+.",
                "evidence": evidence,
            }

        vuln, fixed = is_frappe_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137550"],
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Frappe Framework {ver_display} is vulnerable to CVE-2026-137550 "
                    f"(missing authorization in Document.update(), fixed in {fixed})."
                ),
                "remediation": f"Upgrade Frappe Framework to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137550"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Frappe Framework {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Frappe Framework CVE-2026-137550 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="frappe_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"frappe_version": args.frappe_version} if args.frappe_version else {}
    print(FrappeAuditPlugin(args.target, opts).run_audit())
