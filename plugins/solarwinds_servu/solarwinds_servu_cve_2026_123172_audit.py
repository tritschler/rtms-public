#!/usr/bin/env python3
"""
RTMS Audit Plugin — SolarWinds Serv-U Privilege Escalation, IDOR & TOCTOU Vulnerabilities
Target CVEs (9 critical vulnerabilities, up to CVSS 9.1):
  - CVE-2026-123172, CVE-2026-123168, CVE-2026-123167
  - CVE-2026-82322, CVE-2026-82321, CVE-2026-82320, CVE-2026-82319, CVE-2026-82316, CVE-2026-82315

Affected versions:
  - SolarWinds Serv-U <= 2026.3 (including legacy 15.5.x and earlier; patched in 2026.4)

Strictly read-only passive version check via SolarWinds Serv-U HTTP Server header or web login page.
No file transfer or privilege escalation payloads are sent.
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


SERVU_CVES: List[str] = [
    "CVE-2026-123172",
    "CVE-2026-123168",
    "CVE-2026-123167",
    "CVE-2026-82322",
    "CVE-2026-82321",
    "CVE-2026-82320",
    "CVE-2026-82319",
    "CVE-2026-82316",
    "CVE-2026-82315",
]


def parse_servu_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a SolarWinds Serv-U version string (e.g. '2026.3', '2026.3.0', '15.5.3', 'Serv-U/2026.4')
    into a (major, minor, patch) tuple.
    """
    if not version_str:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_servu_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for the November 2026 Serv-U security update.
    Affected:
      - Legacy 15.x releases
      - CalVer <= 2026.3.x (patched in 2026.4)
    """
    major = version[0]
    if major <= 15:
        return True, "2026.4"
    if 2020 <= major <= 2026 and version < (2026, 4, 0):
        return True, "2026.4"
    return False, "2026.4"


class SolarWindsServUAuditPlugin(BasePlugin):
    name = "solarwinds_servu_cve_2026_123172_audit"
    description = (
        "Passive version check for SolarWinds Serv-U privilege escalation, IDOR, and TOCTOU "
        "vulnerabilities (CVE-2026-123172 and 8 others, CVSS 9.1)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 443))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", True) else "http"
        if ":" in t:
            return f"{scheme}://{t}"
        return f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        patterns = [
            re.compile(r"Serv-U[/\s(v]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        ]

        url = f"{base_url}/"
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
            return None, evidence

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
                evidence.append(f"Version extracted from HTTP body: {ver}")
                return ver, evidence

        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("servu_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied servu_version option: {raw_version}")
        else:
            base_url = self._build_base_url()
            raw_version, probe_ev = self._probe_version(base_url, timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(SERVU_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine SolarWinds Serv-U version.",
                "remediation": "Verify SolarWinds Serv-U version manually and upgrade to 2026.4 or later.",
                "evidence": evidence,
            }

        parsed = parse_servu_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(SERVU_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized SolarWinds Serv-U version format: '{raw_version}'.",
                "remediation": "Upgrade SolarWinds Serv-U to 2026.4 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_servu_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}" if parsed[2] == 0 else f"{parsed[0]}.{parsed[1]}.{parsed[2]}"

        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": list(SERVU_CVES),
                "severity": "CRITICAL",
                "cvss": 9.1,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"SolarWinds Serv-U {ver_display} is vulnerable to CVE-2026-123172 and 8 additional "
                    f"critical privilege escalation / IDOR / TOCTOU vulnerabilities (fixed in {fixed})."
                ),
                "remediation": f"Upgrade SolarWinds Serv-U to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(SERVU_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"SolarWinds Serv-U {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SolarWinds Serv-U CVE-2026-123172 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="servu_version", help="Override detected version string")
    args = parser.parse_args()

    opts = {}
    if args.servu_version:
        opts["servu_version"] = args.servu_version
    plugin = SolarWindsServUAuditPlugin(args.target, opts)
    print(plugin.run_audit())
