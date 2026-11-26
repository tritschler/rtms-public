#!/usr/bin/env python3
"""
RTMS Audit Plugin — Wing FTP Server Predictable Admin Session ID Hijacking
Target CVE:
  - CVE-2026-135171 (CVSS 9.2, Critical): Insufficient entropy in Wing FTP Server
    administrator session token generation (< 8.2.8), allowing remote attackers to
    predict or brute-force active admin session identifiers and execute arbitrary Lua commands.

Affected versions:
  - Wing FTP Server < 8.2.8 (<= 8.2.7, patched in 8.2.8)

Strictly read-only passive version check via Wing FTP Server HTTP header or login banner.
No session guessing or Lua execution is performed.
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


def parse_wing_ftp_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a Wing FTP Server version string (e.g. '8.2.7', 'Wing FTP Server/8.2.8')
    into a (major, minor, patch) tuple.
    """
    if not version_str:
        return None
    m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_wing_ftp_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-135171.
    Affected: < 8.2.8.
    """
    if version < (8, 2, 8):
        return True, "8.2.8"
    return False, "8.2.8"


class WingFTPServerAuditPlugin(BasePlugin):
    name = "wing_ftp_server_cve_2026_135171_audit"
    description = (
        "Passive version check for Wing FTP Server predictable admin session ID hijacking "
        "(CVE-2026-135171, CVSS 9.2)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 5466))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        if ":" in t:
            return f"{scheme}://{t}"
        return f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        patterns = [
            re.compile(r"Wing\s*FTP\s*Server[/\s(v]*([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE),
        ]

        for path in ("/admin_login.html", "/login.html", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "RTMS-Compliance-Audit/1.0"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                try:
                    body = e.read(65536).decode("utf-8", errors="ignore")
                except Exception:
                    body = ""
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            srv = headers.get("server") or ""
            for pat in patterns:
                m = pat.search(srv)
                if m:
                    ver = m.group(1)
                    evidence.append(f"Version extracted from Server header ('{srv}'): {ver}")
                    return ver, evidence

            for pat in patterns:
                m = pat.search(body)
                if m:
                    ver = m.group(1)
                    evidence.append(f"Version extracted from {path}: {ver}")
                    return ver, evidence

        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("wing_ftp_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied wing_ftp_version option: {raw_version}")
        else:
            base_url = self._build_base_url()
            raw_version, probe_ev = self._probe_version(base_url, timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-135171"],
                "severity": "INFO",
                "finding": "Could not passively determine Wing FTP Server version.",
                "remediation": "Verify Wing FTP Server version manually and upgrade to 8.2.8 or later.",
                "evidence": evidence,
            }

        parsed = parse_wing_ftp_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-135171"],
                "severity": "INFO",
                "finding": f"Unrecognized Wing FTP Server version format: '{raw_version}'.",
                "remediation": "Upgrade Wing FTP Server to 8.2.8 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_wing_ftp_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"

        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-135171"],
                "severity": "CRITICAL",
                "cvss": 9.2,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Wing FTP Server {ver_display} is vulnerable to CVE-2026-135171 "
                    f"(predictable administrator session token hijacking, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Wing FTP Server to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-135171"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Wing FTP Server {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wing FTP Server CVE-2026-135171 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="wing_ftp_version", help="Override detected version string")
    args = parser.parse_args()

    opts = {}
    if args.wing_ftp_version:
        opts["wing_ftp_version"] = args.wing_ftp_version
    plugin = WingFTPServerAuditPlugin(args.target, opts)
    print(plugin.run_audit())
