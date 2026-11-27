#!/usr/bin/env python3
"""
RTMS Audit Plugin — HKUDS nanobot TLS Certificate Validation Bypass Audit
Target CVE:
  - CVE-2026-137463 (CVSS 9.1, Critical): HKUDS nanobot from 0.1.4 before 0.4.1 retries
    authenticated requests in the OpenAI Codex provider without TLS certificate or hostname verification.

Strictly read-only passive version check via health/version endpoint or supplied version string.
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


def parse_nanobot_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse an HKUDS nanobot version string (e.g. '0.4.0', '0.4.1') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_nanobot_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-137463 (0.1.4 <= v < 0.4.1)."""
    if (0, 1, 4) <= version < (0, 4, 1):
        return True, "0.4.1"
    return False, "0.4.1"


class HKUDSNanobotAuditPlugin(BasePlugin):
    name = "hkuds_nanobot_cve_2026_137463_audit"
    description = (
        "Passive version check for HKUDS nanobot TLS certificate validation bypass "
        "(CVE-2026-137463, CVSS 9.1)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 8000))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/version", "/health", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "nanobot" not in body.lower():
                continue
            parsed = parse_nanobot_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("nanobot_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied nanobot_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137463"],
                "severity": "INFO",
                "finding": "Could not passively determine HKUDS nanobot version.",
                "remediation": "Upgrade HKUDS nanobot to version 0.4.1 or later.",
                "evidence": evidence,
            }

        parsed = parse_nanobot_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137463"],
                "severity": "INFO",
                "finding": f"Unrecognized HKUDS nanobot version format: '{raw_version}'.",
                "remediation": "Upgrade HKUDS nanobot to version 0.4.1 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_nanobot_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137463"],
                "severity": "CRITICAL",
                "cvss": 9.1,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"HKUDS nanobot {ver_display} is vulnerable to CVE-2026-137463 "
                    f"(improper TLS certificate validation on retry, fixed in {fixed})."
                ),
                "remediation": f"Upgrade HKUDS nanobot to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137463"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"HKUDS nanobot {ver_display} is outside the vulnerable range or >= {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HKUDS nanobot CVE-2026-137463 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="nanobot_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"nanobot_version": args.nanobot_version} if args.nanobot_version else {}
    print(HKUDSNanobotAuditPlugin(args.target, opts).run_audit())
