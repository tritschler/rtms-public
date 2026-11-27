#!/usr/bin/env python3
"""
RTMS Audit Plugin — WordPress Database for CF7, WPForms, Elementor Forms File Upload Audit
Target CVE:
  - CVE-2026-115867 (CVSS 9.8, Critical): Arbitrary File Upload in Database for Contact Form 7,
    WPforms, Elementor forms <= 1.5.5 via missing extension validation in copy_files.

Strictly read-only passive version check via WordPress static plugin metadata.
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


def parse_database_for_cf7_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Database for CF7 plugin version string (e.g. '1.5.5', '1.5.6') into (major, minor, patch)."""
    if not text:
        return None
    patterns = [
        r"/wp-content/plugins/(?:database-for-cf7|database-for-wpforms)/[^\"'\s>]+?\?ver=(\d+)\.(\d+)(?:\.(\d+))?",
        r"(?:Stable\s+tag|Version)\s*:\s*(\d+)\.(\d+)(?:\.(\d+))?",
        r"\b(\d+)\.(\d+)(?:\.(\d+))?\b",
    ]
    for pat in patterns:
        m = re.search(pat, text.strip(), re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return None


def is_database_for_cf7_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-115867 (<= 1.5.5)."""
    if version <= (1, 5, 5):
        return True, "1.5.6"
    return False, "1.5.6"


class WPDatabaseForCF7AuditPlugin(BasePlugin):
    name = "wp_database_for_cf7_cve_2026_115867_audit"
    description = (
        "Passive version check for WordPress Database for CF7, WPForms, Elementor forms "
        "arbitrary file upload (CVE-2026-115867, CVSS 9.8)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "wp_database_for_cf7_cve_2026_115867_audit",
            "description": "Passive version check for WordPress Database for CF7, WPForms, Elementor forms arbitrary file upload (CVE-2026-115867, CVSS 9.8)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-115867",
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

        for path in (
            "/wp-content/plugins/database-for-cf7/readme.txt",
            "/wp-content/plugins/database-for-wpforms/readme.txt",
            "/",
        ):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if path == "/" and "database-for-cf7" not in body.lower() and "database-for-wpforms" not in body.lower():
                continue
            parsed = parse_database_for_cf7_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("plugin_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied plugin_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-115867"],
                "severity": "INFO",
                "finding": "Could not passively determine Database for CF7 plugin version.",
                "remediation": "Ensure Database for Contact Form 7, WPforms, Elementor forms is updated to 1.5.6+.",
                "evidence": evidence,
            }

        parsed = parse_database_for_cf7_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-115867"],
                "severity": "INFO",
                "finding": f"Unrecognized Database for CF7 version format: '{raw_version}'.",
                "remediation": "Update the plugin to version 1.5.6 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_database_for_cf7_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-115867"],
                "severity": "CRITICAL",
                "cvss": 9.8,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Database for CF7/WPForms/Elementor {ver_display} is vulnerable to CVE-2026-115867 "
                    f"(arbitrary file upload via copy_files, <= 1.5.5)."
                ),
                "remediation": f"Upgrade the plugin to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-115867"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Database for CF7/WPForms/Elementor {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WordPress Database for CF7 CVE-2026-115867 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="plugin_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"plugin_version": args.plugin_version} if args.plugin_version else {}
    print(WPDatabaseForCF7AuditPlugin(args.target, opts).run_audit())
