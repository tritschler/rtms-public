#!/usr/bin/env python3
"""
RTMS Audit Plugin — VMware ESX / ESXi I/O Filter & XHCI USB Controller Multi-CVE Audit
Target CVEs:
  - CVE-2026-123910 (CVSS 9.8, Critical): Heap out-of-bounds write in the ESX I/O filter service.
  - CVE-2026-123911 (CVSS 9.8, Critical): Use-after-free vulnerability in the ESX I/O filter service.
  - CVE-2026-123912 (CVSS 9.3, Critical): Out-of-bounds write in the XHCI USB controller in ESXi, Workstation, and Fusion.

Affected versions:
  - VMware ESX / ESXi 9.1.x < 9.1.2.0 (build 25946735)
  - VMware ESX / ESXi 9.0.x < 9.0.2.0200 (build 25953133)
  - VMware ESX / ESXi 8.0.x < 8.0 U3m (build 25926933)
  - VMware Cloud Foundation 5.x < 5.2.5

Strictly read-only passive version check via ESXi SDK vimServiceVersions.xml or UI endpoints.
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


ESXI_CVES: List[str] = ["CVE-2026-123910", "CVE-2026-123911", "CVE-2026-123912"]


def parse_esxi_version(text: str) -> Optional[Tuple[int, int, int, int]]:
    """
    Parse an ESXi version string (e.g. '9.1.1.0', '9.0.2.0200', '8.0 U3l', '8.0 U3m', '5.2.4')
    into a (major, minor, patch, sub) tuple.
    """
    if not text:
        return None
    u_match = re.search(
        r"\b(8)\.(0)(?:\.\d+)?\s*(?:U|Update\s*)(\d)([a-z])?\b",
        text.strip(),
        re.IGNORECASE,
    )
    if u_match:
        upd = int(u_match.group(3))
        letter = (u_match.group(4) or "").lower()
        sub = (ord(letter) - ord("a") + 1) if letter else 0
        return (8, 0, upd, sub)

    m = re.search(r"\b([589])\.(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))


def is_esxi_version_vulnerable(version: Tuple[int, int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-123910 / CVE-2026-123911 / CVE-2026-123912."""
    major, minor, patch, sub = version
    if major == 9 and minor == 1:
        return (version < (9, 1, 2, 0), "9.1.2.0 (build 25946735)")
    if major == 9 and minor == 0:
        return (version < (9, 0, 2, 200), "9.0.2.0200 (build 25953133)")
    if major == 8 and minor == 0:
        threshold_sub = 13 if sub < 100 else 1300
        return (version < (8, 0, 3, threshold_sub), "8.0 U3m (build 25926933)")
    if major == 5:
        return (version < (5, 2, 5, 0), "5.2.5")
    return False, "9.1.2.0 / 9.0.2.0200 / 8.0 U3m / 5.2.5"


class VMwareESXiAuditPlugin(BasePlugin):
    name = "vmware_esxi_cve_2026_123910_audit"
    description = (
        "Passive version check for VMware ESX / ESXi I/O filter & XHCI USB controller vulnerabilities "
        "(CVE-2026-123910, CVE-2026-123911, CVE-2026-123912, CVSS 9.8)"
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

        for path in ("/sdk/vimServiceVersions.xml", "/ui/", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "esxi" not in body.lower() and "vmware" not in body.lower() and "vim25" not in body.lower():
                continue
            parsed = parse_esxi_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}.{parsed[3]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("esxi_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied esxi_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(ESXI_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine VMware ESXi version.",
                "remediation": "Upgrade VMware ESXi to 9.1.2.0, 9.0.2.0200, or 8.0 U3m (KB463501).",
                "evidence": evidence,
            }

        parsed = parse_esxi_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(ESXI_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized VMware ESXi version format: '{raw_version}'.",
                "remediation": "Upgrade VMware ESXi to 9.1.2.0, 9.0.2.0200, or 8.0 U3m.",
                "evidence": evidence,
            }

        vuln, fixed = is_esxi_version_vulnerable(parsed)
        ver_display = str(raw_version)
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": list(ESXI_CVES),
                "severity": "CRITICAL",
                "cvss": 9.8,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"VMware ESXi {ver_display} is vulnerable to CVE-2026-123910, CVE-2026-123911, "
                    f"and CVE-2026-123912 (fixed in {fixed})."
                ),
                "remediation": f"Upgrade VMware ESXi to {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(ESXI_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"VMware ESXi {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VMware ESXi CVE-2026-123910 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="esxi_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"esxi_version": args.esxi_version} if args.esxi_version else {}
    print(VMwareESXiAuditPlugin(args.target, opts).run_audit())
