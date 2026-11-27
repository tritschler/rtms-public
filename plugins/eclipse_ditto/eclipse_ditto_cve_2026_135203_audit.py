#!/usr/bin/env python3
"""
RTMS Audit Plugin — Eclipse Ditto Connectivity Service Mozilla Rhino Sandbox Escape Audit
Target CVE:
  - CVE-2026-135203 (CVSS 9.4, Critical): In Eclipse Ditto versions 0.3.0-M1 through 3.8.15 and
    3.9.0 through 3.9.9, the JavaScript payload mapper of the connectivity service executes
    user-supplied mapping scripts in a Mozilla Rhino engine without a ClassShutter.

Strictly read-only passive version check via Eclipse Ditto status/health endpoints or supplied version string.
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


def parse_eclipse_ditto_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse an Eclipse Ditto version string (e.g. '3.8.15', '3.9.9', '3.9.10') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_eclipse_ditto_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-135203.
    Affected:
      - 0.3.0 <= v <= 3.8.15 (< 3.8.16)
      - 3.9.0 <= v <= 3.9.9 (< 3.9.10)
    """
    if (0, 3, 0) <= version <= (3, 8, 15):
        return True, "3.8.16"
    if (3, 9, 0) <= version <= (3, 9, 9):
        return True, "3.9.10"
    return False, "3.8.16 / 3.9.10"


class EclipseDittoAuditPlugin(BasePlugin):
    name = "eclipse_ditto_cve_2026_135203_audit"
    description = (
        "Passive version check for Eclipse Ditto Mozilla Rhino sandbox escape "
        "(CVE-2026-135203, CVSS 9.4)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "eclipse_ditto_cve_2026_135203_audit",
            "description": "Passive version check for Eclipse Ditto Mozilla Rhino sandbox escape (CVE-2026-135203, CVSS 9.4)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-135203",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 8080))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/status", "/overall/status", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "ditto" not in body.lower():
                continue
            parsed = parse_eclipse_ditto_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("ditto_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied ditto_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-135203"],
                "severity": "INFO",
                "finding": "Could not passively determine Eclipse Ditto version.",
                "remediation": "Upgrade Eclipse Ditto to 3.8.16+ or 3.9.10+.",
                "evidence": evidence,
            }

        parsed = parse_eclipse_ditto_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-135203"],
                "severity": "INFO",
                "finding": f"Unrecognized Eclipse Ditto version format: '{raw_version}'.",
                "remediation": "Upgrade Eclipse Ditto to 3.8.16+ or 3.9.10+.",
                "evidence": evidence,
            }

        vuln, fixed = is_eclipse_ditto_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-135203"],
                "severity": "CRITICAL",
                "cvss": 9.4,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Eclipse Ditto {ver_display} is vulnerable to CVE-2026-135203 "
                    f"(Mozilla Rhino connectivity mapper sandbox escape, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Eclipse Ditto to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-135203"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Eclipse Ditto {ver_display} is at or above patched version ({fixed}).",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Eclipse Ditto CVE-2026-135203 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="ditto_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"ditto_version": args.ditto_version} if args.ditto_version else {}
    print(EclipseDittoAuditPlugin(args.target, opts).run_audit())
