#!/usr/bin/env python3
"""
RTMS Audit Plugin — Budibase Server Prototype Pollution & OIDC/SSO Auth Bypass Audit
Target CVEs:
  - CVE-2026-137498 (CVSS 9.9, Critical): Budibase Server from 3.39.18 before 4.0.0 contains a
    prototype pollution vulnerability allowing unauthenticated attackers to erase MongoDB query filters.
  - CVE-2026-137499 (CVSS 9.3, Critical): Budibase from 3.41.0 before 4.0.0 contains an authentication
    bypass allowing takeover of password-less global Builder accounts via unverified-email OIDC/SSO linking.

Strictly read-only passive version check via Budibase health/version endpoints or supplied version string.
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


BUDIBASE_CVES: List[str] = ["CVE-2026-137498", "CVE-2026-137499"]


def parse_budibase_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Budibase version string (e.g. '3.41.2', '4.0.0') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_budibase_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-137498 (3.39.18 <= v < 4.0.0)
    and CVE-2026-137499 (3.41.0 <= v < 4.0.0).
    """
    if (3, 39, 18) <= version < (4, 0, 0):
        return True, "4.0.0"
    return False, "4.0.0"


class BudibaseAuditPlugin(BasePlugin):
    name = "budibase_cve_2026_137498_audit"
    description = (
        "Passive version check for Budibase Server prototype pollution and OIDC/SSO authentication bypass "
        "(CVE-2026-137498, CVE-2026-137499, CVSS 9.9)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 10000))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/api/global/version", "/version", "/builder"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            parsed = parse_budibase_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("budibase_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied budibase_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(BUDIBASE_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine Budibase version.",
                "remediation": "Upgrade Budibase Server to version 4.0.0 or later.",
                "evidence": evidence,
            }

        parsed = parse_budibase_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(BUDIBASE_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized Budibase version format: '{raw_version}'.",
                "remediation": "Upgrade Budibase Server to version 4.0.0 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_budibase_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": list(BUDIBASE_CVES),
                "severity": "CRITICAL",
                "cvss": 9.9,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Budibase {ver_display} is vulnerable to CVE-2026-137498 and CVE-2026-137499 "
                    f"(prototype pollution & OIDC/SSO authentication bypass, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Budibase Server to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(BUDIBASE_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Budibase {ver_display} is outside the vulnerable range or >= {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Budibase CVE-2026-137498 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="budibase_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"budibase_version": args.budibase_version} if args.budibase_version else {}
    print(BudibaseAuditPlugin(args.target, opts).run_audit())
