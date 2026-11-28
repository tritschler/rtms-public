#!/usr/bin/env python3
"""
RTMS Audit Plugin — TRENDnet TEW-751DR & TEW-733GR UPnP Firmware Compliance Audit
Target CVEs:
  - CVE-2026-138004 (CVSS 9.3, Critical): OS command injection in UPnP IGD endpoint of
    TRENDnet TEW-751DR and TEW-733GR firmware 1.03B01.
  - CVE-2026-138003 (CVSS 9.0, Critical): Stack-based buffer overflow in UPnP/WFA endpoint of
    TRENDnet TEW-751DR firmware 1.03B01.

Strictly read-only passive firmware version check via device status page or supplied firmware string.
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


TRENDNET_CVES: List[str] = ["CVE-2026-138004", "CVE-2026-138003"]


def parse_trendnet_firmware(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a TRENDnet firmware string (e.g. '1.03B01', 'v1.03B02', '1.03.01') into (major, minor, build)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)(?:B|\.)(\d+)\b", text.strip(), re.IGNORECASE)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_trendnet_firmware_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-138004 and CVE-2026-138003 (<= 1.03B01)."""
    if version <= (1, 3, 1):
        return True, "1.03B02"
    return False, "1.03B02"


class TrendnetTEWAuditPlugin(BasePlugin):
    name = "trendnet_tew_cve_2026_138004_audit"
    description = (
        "Passive firmware version check for TRENDnet TEW-751DR and TEW-733GR UPnP vulnerabilities "
        "(CVE-2026-138004, CVE-2026-138003, CVSS 9.3)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "trendnet_tew_cve_2026_138004_audit",
            "description": (
                "Passive firmware version check for TRENDnet TEW-751DR and TEW-733GR UPnP vulnerabilities "
                "(CVE-2026-138004, CVE-2026-138003, CVSS 9.3)"
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-138004, CVE-2026-138003",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 80))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"{base_url}/"
        req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode("utf-8", errors="ignore")
                if "tew-751dr" in body.lower() or "tew-733gr" in body.lower() or "trendnet" in body.lower():
                    parsed = parse_trendnet_firmware(body)
                    if parsed:
                        ver_str = f"{parsed[0]}.{parsed[1]:02d}B{parsed[2]:02d}"
                        evidence.append(f"Firmware extracted from /: {ver_str}")
                        return ver_str, evidence
        except Exception as e:
            evidence.append(f"HTTP probe {url} failed: {e}")
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("firmware_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied firmware_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(TRENDNET_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine TRENDnet TEW-751DR / TEW-733GR firmware version.",
                "remediation": "Upgrade firmware beyond 1.03B01, disable UPnP, or replace EOL hardware.",
                "evidence": evidence,
            }

        parsed = parse_trendnet_firmware(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(TRENDNET_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized TRENDnet firmware version format: '{raw_version}'.",
                "remediation": "Upgrade firmware beyond 1.03B01, disable UPnP, or replace EOL hardware.",
                "evidence": evidence,
            }

        vuln, fixed = is_trendnet_firmware_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]:02d}B{parsed[2]:02d}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": list(TRENDNET_CVES),
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"TRENDnet TEW-751DR / TEW-733GR firmware {ver_display} is vulnerable to "
                    f"CVE-2026-138004 and CVE-2026-138003 (<= 1.03B01)."
                ),
                "remediation": "Disable UPnP immediately and upgrade firmware or decommission affected EOL routers.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(TRENDNET_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"TRENDnet firmware {ver_display} is above affected build 1.03B01.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TRENDnet TEW-751DR / TEW-733GR CVE-2026-138004 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="firmware_version", help="Override detected firmware version string")
    args = parser.parse_args()
    opts = {"firmware_version": args.firmware_version} if args.firmware_version else {}
    print(TrendnetTEWAuditPlugin(args.target, opts).run_audit())
