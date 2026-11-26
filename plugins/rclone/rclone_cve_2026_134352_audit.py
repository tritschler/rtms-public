#!/usr/bin/env python3
"""
RTMS Audit Plugin — Rclone serve sftp --auth-proxy Authentication Bypass
Target CVE:
  - CVE-2026-134352 (CVSS 9.2, Critical): Improper authentication handling in
    `rclone serve sftp --auth-proxy` allowing remote attackers to bypass proxy-based
    key/password validation and access backend cloud remotes without valid credentials.

Affected versions:
  - Rclone 1.51.0 <= version < 1.76.0 (patched in 1.76.0)

Strictly read-only passive version check via SSH/SFTP banner or Rclone HTTP/RC Server header.
No authentication attempts are made.
"""

import argparse
import re
import socket
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


def parse_rclone_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse an Rclone version string (e.g. 'v1.75.2', 'rclone/v1.76.0', '1.68.1')
    into a (major, minor, patch) tuple.
    """
    if not version_str:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_rclone_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-134352.
    Affected: 1.51.0 <= version < 1.76.0.
    """
    if (1, 51, 0) <= version < (1, 76, 0):
        return True, "1.76.0"
    return False, "1.76.0"


class RcloneAuditPlugin(BasePlugin):
    name = "rclone_cve_2026_134352_audit"
    description = (
        "Passive version check for Rclone serve sftp --auth-proxy authentication bypass "
        "(CVE-2026-134352, CVSS 9.2)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _probe_ssh_banner(self, host: str, port: int, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        pat = re.compile(r"rclone[_/\s-]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                if banner:
                    evidence.append(f"SSH/SFTP banner on {host}:{port}: {banner}")
                    m = pat.search(banner)
                    if m:
                        return m.group(1), evidence
        except Exception as e:
            evidence.append(f"TCP banner read on {host}:{port} failed: {e}")
        return None, evidence

    def _probe_http(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        pat = re.compile(r"rclone[/\s-]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)

        req = urllib.request.Request(
            f"{base_url}/",
            headers={"User-Agent": "RTMS-Compliance-Audit/1.0"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                srv = resp.headers.get("Server", "")
        except urllib.error.HTTPError as e:
            srv = e.headers.get("Server", "") if e.headers else ""
        except Exception as e:
            evidence.append(f"HTTP probe {base_url} failed: {e}")
            return None, evidence

        if srv:
            m = pat.search(srv)
            if m:
                evidence.append(f"Version extracted from Server header ('{srv}'): {m.group(1)}")
                return m.group(1), evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("rclone_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied rclone_version option: {raw_version}")
        else:
            t = self.target.strip()
            if t.startswith("http://") or t.startswith("https://"):
                raw_version, ev = self._probe_http(t.rstrip("/"), timeout)
                evidence.extend(ev)
            else:
                host = t.split(":")[0]
                port = int(t.split(":")[1]) if ":" in t else int(self.options.get("port", 2022))
                raw_version, ev = self._probe_ssh_banner(host, port, timeout)
                evidence.extend(ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-134352"],
                "severity": "INFO",
                "finding": "Could not passively determine Rclone version.",
                "remediation": "Verify Rclone version manually (`rclone version`) and upgrade to 1.76.0 or later.",
                "evidence": evidence,
            }

        parsed = parse_rclone_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-134352"],
                "severity": "INFO",
                "finding": f"Unrecognized Rclone version format: '{raw_version}'.",
                "remediation": "Upgrade Rclone to 1.76.0 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_rclone_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"

        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-134352"],
                "severity": "CRITICAL",
                "cvss": 9.2,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Rclone {ver_display} is vulnerable to CVE-2026-134352 "
                    f"(serve sftp --auth-proxy authentication bypass, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Rclone to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-134352"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Rclone {ver_display} is not within the vulnerable range (1.51.0 - 1.75.x).",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rclone CVE-2026-134352 Passive Audit")
    parser.add_argument("--target", required=True, help="Target host:port or URL")
    parser.add_argument("--version", dest="rclone_version", help="Override detected version string")
    args = parser.parse_args()

    opts = {}
    if args.rclone_version:
        opts["rclone_version"] = args.rclone_version
    plugin = RcloneAuditPlugin(args.target, opts)
    print(plugin.run_audit())
