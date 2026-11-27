#!/usr/bin/env python3
"""
RTMS Audit Plugin — WordPress Sneeit Framework Remote Code Execution Audit
Target CVE:
  - CVE-2026-106125 (CVSS 9.8, Critical): Remote Code Execution in Sneeit Framework <= 8.7
    via the callback parameter of the sneeit_compact_menu_mega_content AJAX action.

Strictly read-only passive version check via WordPress static plugin metadata (readme.txt / ?ver=).
No AJAX requests or callback parameters are invoked.
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


def parse_sneeit_framework_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Sneeit Framework version string (e.g. '8.7', '8.8.0') into (major, minor, patch)."""
    if not text:
        return None
    patterns = [
        r"/wp-content/plugins/sneeit-framework/[^\"'\s>]+?\?ver=(\d+)\.(\d+)(?:\.(\d+))?",
        r"(?:Stable\s+tag|Version)\s*:\s*(\d+)\.(\d+)(?:\.(\d+))?",
        r"\b(\d+)\.(\d+)(?:\.(\d+))?\b",
    ]
    for pat in patterns:
        m = re.search(pat, text.strip(), re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return None


def is_sneeit_framework_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-106125 (<= 8.7)."""
    if version <= (8, 7, 0):
        return True, "8.8"
    return False, "8.8"


class WPSneeitFrameworkAuditPlugin(BasePlugin):
    name = "wp_sneeit_framework_cve_2026_106125_audit"
    description = (
        "Passive version check for WordPress Sneeit Framework remote code execution "
        "(CVE-2026-106125, CVSS 9.8)"
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

        for path in (
            "/wp-content/plugins/sneeit-framework/readme.txt",
            "/wp-content/plugins/sneeit-framework/changelog.txt",
            "/",
        ):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if path == "/" and "sneeit-framework" not in body.lower():
                continue
            parsed = parse_sneeit_framework_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("plugin_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied plugin_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-106125"],
                "severity": "INFO",
                "finding": "Could not passively determine WordPress Sneeit Framework version.",
                "remediation": "Ensure Sneeit Framework is updated to version 8.8 or later.",
                "evidence": evidence,
            }

        parsed = parse_sneeit_framework_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-106125"],
                "severity": "INFO",
                "finding": f"Unrecognized Sneeit Framework version format: '{raw_version}'.",
                "remediation": "Update Sneeit Framework to version 8.8 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_sneeit_framework_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}" if parsed[2] == 0 else f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-106125"],
                "severity": "CRITICAL",
                "cvss": 9.8,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Sneeit Framework {ver_display} is vulnerable to CVE-2026-106125 "
                    f"(unauthenticated AJAX callback RCE, <= 8.7)."
                ),
                "remediation": f"Upgrade Sneeit Framework to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-106125"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Sneeit Framework {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WordPress Sneeit Framework CVE-2026-106125 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="plugin_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"plugin_version": args.plugin_version} if args.plugin_version else {}
    print(WPSneeitFrameworkAuditPlugin(args.target, opts).run_audit())
