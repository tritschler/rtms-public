#!/usr/bin/env python3
"""
RTMS Audit Plugin — Canonical LXD OIDC Auth Bypass & pylxd WebSocket TLS Validation Audit
Target CVEs:
  - CVE-2026-135384 (CVSS 9.2, Critical): Improper authentication in OIDC bearer token verification
    in Canonical LXD before 5.0.12, 5.21.10, and 6.10.2.
  - CVE-2026-127163 (CVSS 9.1, Critical): Improper certificate validation in WebSocket connections
    in Canonical pylxd before 2.4.3.

Strictly read-only passive version check via LXD `/1.0` metadata endpoint or supplied version string.
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


LXD_CVES: List[str] = ["CVE-2026-135384", "CVE-2026-127163"]


def parse_lxd_version(text: str) -> Optional[Tuple[str, int, int, int]]:
    """
    Parse a Canonical LXD or pylxd version string (e.g. '5.21.9', '6.10.2', 'pylxd 2.4.2')
    into (component, major, minor, patch) where component is 'lxd' or 'pylxd'.
    """
    if not text:
        return None
    comp = "pylxd" if "pylxd" in text.lower() else "lxd"
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (comp, int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_lxd_version_vulnerable(parsed: Tuple[str, int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-135384 (LXD) and CVE-2026-127163 (pylxd).
    """
    comp, major, minor, patch = parsed
    ver = (major, minor, patch)
    if comp == "pylxd" or major == 2:
        return (ver < (2, 4, 3), "2.4.3")
    if major == 5 and minor == 0:
        return (ver < (5, 0, 12), "5.0.12")
    if major == 5 and minor <= 21:
        return (ver < (5, 21, 10), "5.21.10")
    if major == 6:
        return (ver < (6, 10, 2), "6.10.2")
    return False, "5.0.12 / 5.21.10 / 6.10.2"


class CanonicalLXDAuditPlugin(BasePlugin):
    name = "canonical_lxd_cve_2026_135384_audit"
    description = (
        "Passive version check for Canonical LXD OIDC authentication bypass & pylxd TLS validation "
        "(CVE-2026-135384, CVE-2026-127163, CVSS 9.2)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 8443))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", True) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"{base_url}/1.0"
        req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode("utf-8", errors="ignore")
                m = re.search(r'"server_version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"', body)
                if m:
                    ver = m.group(1)
                    evidence.append(f"server_version extracted from /1.0: {ver}")
                    return ver, evidence
        except Exception as e:
            evidence.append(f"HTTP probe {url} failed: {e}")
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("lxd_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied lxd_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(LXD_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine Canonical LXD / pylxd version.",
                "remediation": "Upgrade LXD to 5.0.12 / 5.21.10 / 6.10.2+ and pylxd to 2.4.3+.",
                "evidence": evidence,
            }

        parsed = parse_lxd_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(LXD_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized LXD / pylxd version format: '{raw_version}'.",
                "remediation": "Upgrade LXD to 5.0.12 / 5.21.10 / 6.10.2+ and pylxd to 2.4.3+.",
                "evidence": evidence,
            }

        vuln, fixed = is_lxd_version_vulnerable(parsed)
        comp, major, minor, patch = parsed
        ver_display = f"{major}.{minor}.{patch}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": list(LXD_CVES),
                "severity": "CRITICAL",
                "cvss": 9.2,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Canonical {comp.upper()} {ver_display} is vulnerable to CVE-2026-135384 / "
                    f"CVE-2026-127163 (fixed in {fixed})."
                ),
                "remediation": f"Upgrade Canonical {comp} to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(LXD_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Canonical {comp.upper()} {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Canonical LXD & pylxd CVE-2026-135384 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="lxd_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"lxd_version": args.lxd_version} if args.lxd_version else {}
    print(CanonicalLXDAuditPlugin(args.target, opts).run_audit())
