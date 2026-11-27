#!/usr/bin/env python3
"""
RTMS Audit Plugin — Coder AWS IAM Database Password Disclosure Audit
Target CVE:
  - CVE-2026-137547 (CVSS 9.2, Critical): Coder before 2.29.27, 2.30.0 before 2.34.19,
    2.35.0 before 2.37.11, 2.38.0 before 2.38.7, and 2.39.0 before 2.39.1 returns database
    connection errors containing a temporary AWS IAM database password in API key middleware responses.

Strictly read-only passive version check via Coder `/api/v2/buildinfo` endpoint or supplied version string.
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


def parse_coder_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Coder version string (e.g. 'v2.38.6', '2.39.1+abc') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_coder_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-137547.
    Affected:
      - < 2.29.27
      - 2.30.0 <= v < 2.34.19
      - 2.35.0 <= v < 2.37.11
      - 2.38.0 <= v < 2.38.7
      - 2.39.0 <= v < 2.39.1
    """
    if version < (2, 29, 27):
        return True, "2.29.27"
    if (2, 30, 0) <= version < (2, 34, 19):
        return True, "2.34.19"
    if (2, 35, 0) <= version < (2, 37, 11):
        return True, "2.37.11"
    if (2, 38, 0) <= version < (2, 38, 7):
        return True, "2.38.7"
    if (2, 39, 0) <= version < (2, 39, 1):
        return True, "2.39.1"
    return False, "2.29.27 / 2.34.19 / 2.37.11 / 2.38.7 / 2.39.1"


class CoderAuditPlugin(BasePlugin):
    name = "coder_cve_2026_137547_audit"
    description = (
        "Passive version check for Coder AWS IAM database credential disclosure "
        "(CVE-2026-137547, CVSS 9.2)"
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

        url = f"{base_url}/api/v2/buildinfo"
        req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode("utf-8", errors="ignore")
                m = re.search(r'"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+)', body)
                if m:
                    ver = m.group(1)
                    evidence.append(f"Version extracted from /api/v2/buildinfo: {ver}")
                    return ver, evidence
        except Exception as e:
            evidence.append(f"HTTP probe {url} failed: {e}")
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("coder_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied coder_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137547"],
                "severity": "INFO",
                "finding": "Could not passively determine Coder version.",
                "remediation": "Upgrade Coder to 2.29.27, 2.34.19, 2.37.11, 2.38.7, or 2.39.1+.",
                "evidence": evidence,
            }

        parsed = parse_coder_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137547"],
                "severity": "INFO",
                "finding": f"Unrecognized Coder version format: '{raw_version}'.",
                "remediation": "Upgrade Coder to 2.29.27, 2.34.19, 2.37.11, 2.38.7, or 2.39.1+.",
                "evidence": evidence,
            }

        vuln, fixed = is_coder_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137547"],
                "severity": "CRITICAL",
                "cvss": 9.2,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Coder {ver_display} is vulnerable to CVE-2026-137547 "
                    f"(AWS IAM database password disclosure in API key middleware, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Coder to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137547"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Coder {ver_display} is at or above patched version ({fixed}).",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Coder CVE-2026-137547 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="coder_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"coder_version": args.coder_version} if args.coder_version else {}
    print(CoderAuditPlugin(args.target, opts).run_audit())
