#!/usr/bin/env python3
"""
RTMS Audit Plugin — SEPPmail Secure E-Mail Gateway Multi-CVE Audit
Target CVEs:
  - CVE-2026-130637 (CVSS 9.3, Critical): Pre-authentication Server-Side Template Injection (SSTI)
    in SEPPmail Secure E-Mail Gateway before 15.1.2.
  - CVE-2026-124843 (CVSS 9.2, Critical): Hard-coded fallback secret for legacy GINA token and Large
    File Transfer (LFT) cryptographic operations before 15.1.2.
  - CVE-2026-124840 (CVSS 9.2, Critical): Broad legacy GINA session purpose reuse across registration
    and recovery workflows before 15.1.2.

Strictly read-only passive version check via SEPPmail web portal metadata or supplied version string.
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


SEPPMAIL_CVES: List[str] = ["CVE-2026-130637", "CVE-2026-124843", "CVE-2026-124840"]


def parse_seppmail_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a SEPPmail Secure Email Gateway version string (e.g. '15.1.1', '15.1.2') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_seppmail_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-130637 / CVE-2026-124843 / CVE-2026-124840 (< 15.1.2)."""
    if version < (15, 1, 2):
        return True, "15.1.2"
    return False, "15.1.2"


class SEPPmailAuditPlugin(BasePlugin):
    name = "seppmail_cve_2026_130637_audit"
    description = (
        "Passive version check for SEPPmail Secure E-Mail Gateway pre-auth SSTI and GINA cryptographic flaws "
        "(CVE-2026-130637, CVE-2026-124843, CVE-2026-124840, CVSS 9.3)"
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

        for path in ("/", "/webmail/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "seppmail" not in body.lower() and "gina" not in body.lower():
                continue
            parsed = parse_seppmail_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("seppmail_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied seppmail_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(SEPPMAIL_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine SEPPmail Secure E-Mail Gateway version.",
                "remediation": "Upgrade SEPPmail Secure E-Mail Gateway to version 15.1.2 or later.",
                "evidence": evidence,
            }

        parsed = parse_seppmail_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(SEPPMAIL_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized SEPPmail version format: '{raw_version}'.",
                "remediation": "Upgrade SEPPmail Secure E-Mail Gateway to version 15.1.2 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_seppmail_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": list(SEPPMAIL_CVES),
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"SEPPmail Secure E-Mail Gateway {ver_display} is vulnerable to CVE-2026-130637, "
                    f"CVE-2026-124843, and CVE-2026-124840 (fixed in {fixed})."
                ),
                "remediation": f"Upgrade SEPPmail Secure E-Mail Gateway to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(SEPPMAIL_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"SEPPmail Secure E-Mail Gateway {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SEPPmail Secure E-Mail Gateway CVE-2026-130637 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="seppmail_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"seppmail_version": args.seppmail_version} if args.seppmail_version else {}
    print(SEPPmailAuditPlugin(args.target, opts).run_audit())
