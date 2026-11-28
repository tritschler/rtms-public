#!/usr/bin/env python3
"""
RTMS Audit Plugin — Mendix OIDC Provider JWT Integrity Validation Bypass Audit
Target CVE:
  - CVE-2026-124981 (CVSS 9.4, Critical): Mendix OIDC Provider (< V4.3.0 for Mendix 9;
    < V6.0.0 for Mendix 10 and Mendix 11) does not properly validate the integrity of JWTs
    submitted to the Token Introspection endpoint.

Strictly read-only passive version check via Mendix OIDC metadata or supplied version string.
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


def parse_mendix_oidc_version(text: str, default_mendix_major: int = 10) -> Optional[Tuple[int, int, int, int]]:
    """
    Parse a Mendix OIDC Provider version string (e.g. '5.4.0', 'V6.0.0', 'mendix9:4.2.1', 'Mendix 9 V4.3.0')
    into (mendix_major, major, minor, patch).
    """
    if not text:
        return None
    s = text.strip()
    mendix_major = default_mendix_major
    m_mx = re.search(r"(?:mendix\s*|mx)(\d+)\b|^(\d+)\s*:", s, re.IGNORECASE)
    if m_mx:
        mendix_major = int(m_mx.group(1) or m_mx.group(2))
        s = s[m_mx.end():]
    m_ver = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", s, re.IGNORECASE)
    if not m_ver:
        return None
    major, minor, patch = int(m_ver.group(1)), int(m_ver.group(2)), int(m_ver.group(3) or 0)
    return (mendix_major, major, minor, patch)


def is_mendix_oidc_version_vulnerable(parsed: Tuple[int, int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-124981:
      - Mendix 9 compatible track: < 4.3.0
      - Mendix 10 / 11 compatible track: < 6.0.0
    """
    mx_major, major, minor, patch = parsed
    ver = (major, minor, patch)
    if mx_major == 9:
        return (ver < (4, 3, 0), "4.3.0")
    return (ver < (6, 0, 0), "6.0.0")


class MendixOIDCAuditPlugin(BasePlugin):
    name = "mendix_oidc_cve_2026_124981_audit"
    description = (
        "Passive version check for Mendix OIDC Provider JWT token introspection validation bypass "
        "(CVE-2026-124981, CVSS 9.4)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "mendix_oidc_cve_2026_124981_audit",
            "description": (
                "Passive version check for Mendix OIDC Provider JWT token introspection validation bypass "
                "(CVE-2026-124981, CVSS 9.4)"
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-124981",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

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

        for path in ("/oauth/v2/metadata", "/.well-known/openid-configuration"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            m = re.search(r'"(?:module_version|oidc_provider_version|version)"\s*:\s*"([^"]+)"', body, re.IGNORECASE)
            if m:
                ver_str = m.group(1)
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("oidc_version")
        mendix_major = int(self.options.get("mendix_major", 10))
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied oidc_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-124981"],
                "severity": "INFO",
                "finding": "Could not passively determine Mendix OIDC Provider module version.",
                "remediation": "Upgrade Mendix OIDC Provider to V6.0.0+ (Mendix 10/11) or V4.3.0+ (Mendix 9).",
                "evidence": evidence,
            }

        parsed = parse_mendix_oidc_version(str(raw_version), default_mendix_major=mendix_major)
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-124981"],
                "severity": "INFO",
                "finding": f"Unrecognized Mendix OIDC Provider version format: '{raw_version}'.",
                "remediation": "Upgrade Mendix OIDC Provider to V6.0.0+ (Mendix 10/11) or V4.3.0+ (Mendix 9).",
                "evidence": evidence,
            }

        vuln, fixed = is_mendix_oidc_version_vulnerable(parsed)
        mx_maj, major, minor, patch = parsed
        ver_display = f"{major}.{minor}.{patch}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-124981"],
                "severity": "CRITICAL",
                "cvss": 9.4,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Mendix OIDC Provider {ver_display} (Mendix {mx_maj}) is vulnerable to CVE-2026-124981 "
                    f"(missing JWT integrity verification on Token Introspection, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Mendix OIDC Provider module to V{fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-124981"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Mendix OIDC Provider {ver_display} (Mendix {mx_maj}) is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mendix OIDC Provider CVE-2026-124981 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="oidc_version", help="Override detected OIDC module version string")
    parser.add_argument("--mendix-major", type=int, default=10, help="Mendix major release (9, 10, or 11)")
    args = parser.parse_args()
    opts: Dict = {"mendix_major": args.mendix_major}
    if args.oidc_version:
        opts["oidc_version"] = args.oidc_version
    print(MendixOIDCAuditPlugin(args.target, opts).run_audit())
