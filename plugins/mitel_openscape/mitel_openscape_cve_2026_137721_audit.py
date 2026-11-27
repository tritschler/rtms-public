#!/usr/bin/env python3
"""
RTMS Audit Plugin — Mitel OpenScape 4000 & OpenScape 4000 Manager Multi-CVE Audit
Target CVEs:
  - CVE-2026-137721 (CVSS 10.0, Critical): Command injection in the Platform component (MTLVULN-1786).
  - CVE-2026-137724 (CVSS 10.0, Critical): Unauthenticated unauthorized access due to improper authentication (MTLVULN-1785).
  - CVE-2026-137723 (CVSS 9.6, Critical): Command injection in the Platform component (MTLVULN-1793).

Affected versions:
  - OpenScape 4000 / OpenScape 4000 Manager V11 R0.22 through V11 R2.11 (fixed in V11 R2.12)
  - OpenScape 4000 / OpenScape 4000 Manager V10 R1.68 and earlier (fixed in V10 R1.69)

Strictly read-only passive version check via web portal metadata or supplied version string.
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


MITEL_OPENSCAPE_CVES: List[str] = ["CVE-2026-137721", "CVE-2026-137723", "CVE-2026-137724"]


def parse_mitel_openscape_version(text: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a Mitel OpenScape 4000 version string (e.g. 'V11 R2.11', 'V10 R1.68', '11.2.11', '11.2.12')
    into (major_v, release_r, minor_m).
    """
    if not text:
        return None
    vr = re.search(r"V?(\d{1,2})\s*R(\d+)\.(\d+)", text.strip(), re.IGNORECASE)
    if vr:
        return (int(vr.group(1)), int(vr.group(2)), int(vr.group(3)))
    m = re.search(r"\b(10|11)\.(\d+)\.(\d+)\b", text.strip())
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def is_mitel_openscape_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-137721 / CVE-2026-137723 / CVE-2026-137724.
    Affected:
      - V10 <= R1.68 (< (10, 1, 69))
      - V11 R0.22 through V11 R2.11 ((11, 0, 22) <= v <= (11, 2, 11))
    """
    major = version[0]
    if major == 10:
        return (version <= (10, 1, 68), "V10 R1.69")
    if major == 11:
        return ((11, 0, 22) <= version <= (11, 2, 11), "V11 R2.12")
    return False, "V11 R2.12 / V10 R1.69"


class MitelOpenScapeAuditPlugin(BasePlugin):
    name = "mitel_openscape_cve_2026_137721_audit"
    description = (
        "Passive version check for Mitel OpenScape 4000 & OpenScape 4000 Manager command injection "
        "and authentication bypass (CVE-2026-137721, CVE-2026-137723, CVE-2026-137724, CVSS 10.0)"
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

        for path in ("/", "/ login", "/openscape"):
            url = f"{base_url}{path.strip()}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "openscape" not in body.lower():
                continue
            parsed = parse_mitel_openscape_version(body)
            if parsed:
                ver_str = f"V{parsed[0]} R{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("openscape_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied openscape_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(MITEL_OPENSCAPE_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine Mitel OpenScape 4000 version.",
                "remediation": "Upgrade Mitel OpenScape 4000 / Manager to V11 R2.12+ or V10 R1.69+.",
                "evidence": evidence,
            }

        parsed = parse_mitel_openscape_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(MITEL_OPENSCAPE_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized Mitel OpenScape 4000 version format: '{raw_version}'.",
                "remediation": "Upgrade Mitel OpenScape 4000 / Manager to V11 R2.12+ or V10 R1.69+.",
                "evidence": evidence,
            }

        vuln, fixed = is_mitel_openscape_version_vulnerable(parsed)
        ver_display = f"V{parsed[0]} R{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": list(MITEL_OPENSCAPE_CVES),
                "severity": "CRITICAL",
                "cvss": 10.0,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Mitel OpenScape 4000 {ver_display} is vulnerable to CVE-2026-137721, "
                    f"CVE-2026-137723, and CVE-2026-137724 (fixed in {fixed})."
                ),
                "remediation": f"Upgrade Mitel OpenScape 4000 / Manager to {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(MITEL_OPENSCAPE_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Mitel OpenScape 4000 {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mitel OpenScape 4000 CVE-2026-137721 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="openscape_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"openscape_version": args.openscape_version} if args.openscape_version else {}
    print(MitelOpenScapeAuditPlugin(args.target, opts).run_audit())
