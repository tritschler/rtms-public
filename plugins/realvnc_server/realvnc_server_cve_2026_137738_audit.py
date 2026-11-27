#!/usr/bin/env python3
"""
RTMS Audit Plugin — RealVNC Server Unauthenticated UDP Remote Code Execution Audit
Target CVE:
  - CVE-2026-137738 (CVSS 9.8, Critical): In RealVNC Server before 7.19.1 (6.4.0 through 7.19.0),
    UDP-based connections could be exploited without authentication to execute code remotely or crash the server.

Strictly read-only passive version check via HTTP/RFB banner or supplied version metadata.
No UDP packets or exploitation attempts are sent.
"""

import argparse
import re
import socket
from typing import Dict, List, Optional, Tuple

try:
    from core.plugin_base import BasePlugin
except ImportError:

    class BasePlugin:
        def __init__(self, target: str, options: Optional[Dict] = None):
            self.target = target
            self.options = options or {}


def parse_realvnc_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a RealVNC Server version string (e.g. '7.19.0', '7.19.1', 'RealVNC/7.18.2') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_realvnc_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-137738.
    Affected: RealVNC Server 6.4.0 through 7.19.0 (< 7.19.1).
    """
    if (6, 4, 0) <= version < (7, 19, 1):
        return True, "7.19.1"
    return False, "7.19.1"


class RealVNCServerAuditPlugin(BasePlugin):
    name = "realvnc_server_cve_2026_137738_audit"
    description = (
        "Passive version check for RealVNC Server unauthenticated UDP RCE / DoS "
        "(CVE-2026-137738, CVSS 9.8)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "realvnc_server_cve_2026_137738_audit",
            "description": "Passive version check for RealVNC Server unauthenticated UDP RCE / DoS (CVE-2026-137738, CVSS 9.8)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-137738",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _probe_version(self, host: str, port: int, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                if banner:
                    evidence.append(f"TCP banner on {host}:{port}: {banner}")
                    m = re.search(r"RealVNC[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", banner, re.IGNORECASE)
                    if m:
                        return m.group(1), evidence
        except Exception as e:
            evidence.append(f"Banner read on {host}:{port} failed: {e}")
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 5))
        port = int(self.options.get("port", 5900))
        raw_version = self.options.get("realvnc_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied realvnc_version option: {raw_version}")
        else:
            host = self.target.strip().split("://")[-1].split(":")[0].split("/")[0]
            raw_version, probe_ev = self._probe_version(host, port, timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137738"],
                "severity": "INFO",
                "finding": "Could not passively determine RealVNC Server version.",
                "remediation": "Verify RealVNC Server version and upgrade to 7.19.1 or later.",
                "evidence": evidence,
            }

        parsed = parse_realvnc_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137738"],
                "severity": "INFO",
                "finding": f"Unrecognized RealVNC Server version format: '{raw_version}'.",
                "remediation": "Upgrade RealVNC Server to 7.19.1 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_realvnc_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137738"],
                "severity": "CRITICAL",
                "cvss": 9.8,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"RealVNC Server {ver_display} is vulnerable to CVE-2026-137738 "
                    f"(unauthenticated UDP RCE / crash, fixed in {fixed})."
                ),
                "remediation": f"Upgrade RealVNC Server to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137738"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"RealVNC Server {ver_display} is outside the vulnerable range or >= {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RealVNC Server CVE-2026-137738 Passive Audit")
    parser.add_argument("--target", required=True, help="Target hostname or IP")
    parser.add_argument("--version", dest="realvnc_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"realvnc_version": args.realvnc_version} if args.realvnc_version else {}
    print(RealVNCServerAuditPlugin(args.target, opts).run_audit())
