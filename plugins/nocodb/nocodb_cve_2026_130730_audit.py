#!/usr/bin/env python3
"""
RTMS Audit Plugin — NocoDB OAuth / JWT Authentication Bypass
Target CVE:
  - CVE-2026-130730 (CVSS 9.3, Critical): Improper validation of OAuth / JWT token claims
    allowing an unauthenticated remote attacker to forge or bypass user authentication and
    gain unauthorized administrative access to NocoDB workspaces.

Affected versions:
  - NocoDB < 2026.10.1 (patched in 2026.10.1)
  - Legacy 0.x releases <= 0.265.0

Strictly read-only passive version check via NocoDB public info/health endpoints or
response headers. No exploit payloads or authentication bypass attempts are sent.
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


def parse_nocodb_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a NocoDB version string (e.g. '2026.10.0', '2026.10.1', '0.258.2')
    into a (major, minor, patch) tuple.
    """
    if not version_str:
        return None
    m = re.search(r"\b(\d{4}|\d+)\.(\d+)(?:\.(\d+))?\b", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_nocodb_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-130730.
    Affected:
      - CalVer (< 2026.10.1)
      - Legacy 0.x (< 2026.10.1)
    """
    major = version[0]
    if major == 0:
        return True, "2026.10.1"
    if 2020 <= major <= 2026 and version < (2026, 10, 1):
        return True, "2026.10.1"
    return False, "2026.10.1"


class NocoDBAuditPlugin(BasePlugin):
    name = "nocodb_cve_2026_130730_audit"
    description = (
        "Passive version check for NocoDB OAuth/JWT authentication bypass "
        "(CVE-2026-130730, CVSS 9.3)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "nocodb_cve_2026_130730_audit",
            "description": "Passive version check for NocoDB OAuth/JWT authentication bypass (CVE-2026-130730, CVSS 9.3)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-130730",
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
        if ":" in t:
            return f"{scheme}://{t}"
        return f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        patterns = [
            re.compile(r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"', re.IGNORECASE),
            re.compile(r"NocoDB[^0-9]{0,20}v?([0-9]{4}\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        ]

        for path in ("/api/v1/db/meta/nocodb/info", "/api/v2/meta/nocodb/info", "/dashboard"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "RTMS-Compliance-Audit/1.0", "Accept": "application/json,text/html"},
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

            ver_hdr = headers.get("x-nocodb-version") or ""
            if ver_hdr:
                evidence.append(f"X-NocoDB-Version header on {path}: {ver_hdr}")
                return ver_hdr, evidence

            for pat in patterns:
                m = pat.search(body)
                if m:
                    ver = m.group(1)
                    evidence.append(f"Version extracted from {path}: {ver}")
                    return ver, evidence

        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("nocodb_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied nocodb_version option: {raw_version}")
        else:
            base_url = self._build_base_url()
            raw_version, probe_ev = self._probe_version(base_url, timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-130730"],
                "severity": "INFO",
                "finding": "Could not passively determine NocoDB version.",
                "remediation": (
                    "Verify NocoDB version manually and ensure it is upgraded to 2026.10.1 or later."
                ),
                "evidence": evidence,
            }

        parsed = parse_nocodb_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-130730"],
                "severity": "INFO",
                "finding": f"Unrecognized NocoDB version format: '{raw_version}'.",
                "remediation": "Upgrade NocoDB to 2026.10.1 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_nocodb_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"

        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-130730"],
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"NocoDB {ver_display} is vulnerable to CVE-2026-130730 "
                    f"(OAuth / JWT authentication bypass, fixed in {fixed})."
                ),
                "remediation": f"Upgrade NocoDB to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-130730"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"NocoDB {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NocoDB CVE-2026-130730 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="nocodb_version", help="Override detected version string")
    args = parser.parse_args()

    opts = {}
    if args.nocodb_version:
        opts["nocodb_version"] = args.nocodb_version
    plugin = NocoDBAuditPlugin(args.target, opts)
    print(plugin.run_audit())
