#!/usr/bin/env python3
"""
RTMS Audit Plugin — Twenty CRM Multi-Workspace Invitation Token Authentication Bypass Audit
Target CVE:
  - CVE-2026-137584 (CVSS 9.1, Critical): Twenty through 2.63.0 in multi-workspace mode contains
    an authentication bypass vulnerability allowing unauthenticated attackers to obtain pending
    invitation tokens by registering an invitee's email via the signUp GraphQL mutation.

Strictly read-only passive version check via Twenty healthz/version metadata or supplied version string.
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


def parse_twenty_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Twenty CRM version string (e.g. '2.63.0', '2.63.1', 'v2.63.0') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_twenty_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-137584 (<= 2.63.0)."""
    if version <= (2, 63, 0):
        return True, "2.63.1"
    return False, "2.63.1"


class TwentyCRMAuditPlugin(BasePlugin):
    name = "twenty_crm_cve_2026_137584_audit"
    description = (
        "Passive version check for Twenty CRM multi-workspace authentication bypass "
        "(CVE-2026-137584, CVSS 9.1)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 3000))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/healthz", "/version", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "twenty" not in body.lower() and path == "/":
                continue
            parsed = parse_twenty_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("twenty_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied twenty_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137584"],
                "severity": "INFO",
                "finding": "Could not passively determine Twenty CRM version.",
                "remediation": "Upgrade Twenty CRM to version 2.63.1 or later.",
                "evidence": evidence,
            }

        parsed = parse_twenty_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137584"],
                "severity": "INFO",
                "finding": f"Unrecognized Twenty CRM version format: '{raw_version}'.",
                "remediation": "Upgrade Twenty CRM to version 2.63.1 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_twenty_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137584"],
                "severity": "CRITICAL",
                "cvss": 9.1,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Twenty CRM {ver_display} is vulnerable to CVE-2026-137584 "
                    f"(multi-workspace invitation token authentication bypass, <= 2.63.0)."
                ),
                "remediation": f"Upgrade Twenty CRM to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137584"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Twenty CRM {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Twenty CRM CVE-2026-137584 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="twenty_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"twenty_version": args.twenty_version} if args.twenty_version else {}
    print(TwentyCRMAuditPlugin(args.target, opts).run_audit())
