#!/usr/bin/env python3
"""
RTMS Audit Plugin — WordPress Simple Membership Privilege Escalation Audit
Target CVE:
  - CVE-2026-133951 (CVSS 9.1, Critical): Privilege Escalation in Simple Membership <= 4.8.9
    due to weak non-cryptographic generation of swpm_private_key_one.

Strictly read-only passive version check via WordPress static plugin metadata.
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


def parse_simple_membership_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Simple Membership version string (e.g. '4.8.9', '4.8.10') into (major, minor, patch)."""
    if not text:
        return None
    patterns = [
        r"/wp-content/plugins/simple-membership/[^\"'\s>]+?\?ver=(\d+)\.(\d+)(?:\.(\d+))?",
        r"(?:Stable\s+tag|Version)\s*:\s*(\d+)\.(\d+)(?:\.(\d+))?",
        r"\b(\d+)\.(\d+)(?:\.(\d+))?\b",
    ]
    for pat in patterns:
        m = re.search(pat, text.strip(), re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return None


def is_simple_membership_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-133951 (<= 4.8.9)."""
    if version <= (4, 8, 9):
        return True, "4.8.10"
    return False, "4.8.10"


class WPSimpleMembershipAuditPlugin(BasePlugin):
    name = "wp_simple_membership_cve_2026_133951_audit"
    description = (
        "Passive version check for WordPress Simple Membership privilege escalation "
        "(CVE-2026-133951, CVSS 9.1)"
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

        for path in ("/wp-content/plugins/simple-membership/readme.txt", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if path == "/" and "simple-membership" not in body.lower():
                continue
            parsed = parse_simple_membership_version(body)
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
                "cve": ["CVE-2026-133951"],
                "severity": "INFO",
                "finding": "Could not passively determine Simple Membership plugin version.",
                "remediation": "Ensure Simple Membership (simple-membership) is updated to 4.8.10 or later.",
                "evidence": evidence,
            }

        parsed = parse_simple_membership_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-133951"],
                "severity": "INFO",
                "finding": f"Unrecognized Simple Membership version format: '{raw_version}'.",
                "remediation": "Update Simple Membership to 4.8.10 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_simple_membership_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-133951"],
                "severity": "CRITICAL",
                "cvss": 9.1,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Simple Membership {ver_display} is vulnerable to CVE-2026-133951 "
                    f"(privilege escalation via weak signing key, <= 4.8.9)."
                ),
                "remediation": f"Upgrade Simple Membership to version {fixed} or later and rotate signing keys.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-133951"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Simple Membership {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WordPress Simple Membership CVE-2026-133951 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="plugin_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"plugin_version": args.plugin_version} if args.plugin_version else {}
    print(WPSimpleMembershipAuditPlugin(args.target, opts).run_audit())
