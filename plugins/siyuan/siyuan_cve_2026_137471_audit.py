#!/usr/bin/env python3
"""
RTMS Audit Plugin — SiYuan WebDAV Error Rendering XSS / RCE Audit
Target CVE:
  - CVE-2026-137471 (CVSS 9.0, Critical): SiYuan before 3.8.10 skips HTML escaping for certain
    malformed-response WebDAV sync errors, passing raw markup to the Electron notification renderer.

Strictly read-only passive version check via SiYuan version API or HTML title/meta tags.
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


def parse_siyuan_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a SiYuan version string (e.g. '3.8.9', '3.8.10', 'v3.8.9') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_siyuan_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-137471 (< 3.8.10)."""
    if version < (3, 8, 10):
        return True, "3.8.10"
    return False, "3.8.10"


class SiYuanAuditPlugin(BasePlugin):
    name = "siyuan_cve_2026_137471_audit"
    description = (
        "Passive version check for SiYuan WebDAV error rendering XSS "
        "(CVE-2026-137471, CVSS 9.0)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "siyuan_cve_2026_137471_audit",
            "description": "Passive version check for SiYuan WebDAV error rendering XSS (CVE-2026-137471, CVSS 9.0)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-137471",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 6806))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/api/system/version", "/stage/build/desktop/", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "siyuan" not in body.lower() and path == "/":
                continue
            parsed = parse_siyuan_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("siyuan_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied siyuan_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137471"],
                "severity": "INFO",
                "finding": "Could not passively determine SiYuan version.",
                "remediation": "Upgrade SiYuan to version 3.8.10 or later.",
                "evidence": evidence,
            }

        parsed = parse_siyuan_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137471"],
                "severity": "INFO",
                "finding": f"Unrecognized SiYuan version format: '{raw_version}'.",
                "remediation": "Upgrade SiYuan to version 3.8.10 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_siyuan_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137471"],
                "severity": "CRITICAL",
                "cvss": 9.0,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"SiYuan {ver_display} is vulnerable to CVE-2026-137471 "
                    f"(WebDAV sync error formatting XSS in Electron renderer, fixed in {fixed})."
                ),
                "remediation": f"Upgrade SiYuan to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137471"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"SiYuan {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SiYuan CVE-2026-137471 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="siyuan_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"siyuan_version": args.siyuan_version} if args.siyuan_version else {}
    print(SiYuanAuditPlugin(args.target, opts).run_audit())
