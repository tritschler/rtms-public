#!/usr/bin/env python3
"""
RTMS Audit Plugin — Drupal Core Multi-CVE Access Control & Forceful Browsing Audit
Target CVEs:
  - CVE-2026-136716 (CVSS 9.8, Critical): Improper Check for Unusual or Exceptional Conditions
    in Drupal core (0.0.0–10.6.23, 11.0.0–11.3.23, 11.4.0–11.4.14) allowing Forceful Browsing.
  - CVE-2026-132165 (CVSS 9.8, Critical): Missing Authentication for Critical Function in Drupal core
    (0.0.0–10.6.22, 11.0.0–11.3.22, 11.4.0–11.4.13) allowing access control bypass.

Strictly read-only passive version check via Drupal headers, meta generator tags, or CHANGELOG.txt.
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


DRUPAL_CVES: List[str] = ["CVE-2026-136716", "CVE-2026-132165"]


def parse_drupal_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a Drupal core version string (e.g. '10.6.23', 'Drupal 11.4.14') into (major, minor, patch)."""
    if not text:
        return None
    patterns = [
        r"Drupal\s+(\d+)\.(\d+)(?:\.(\d+))?",
        r"\b(\d+)\.(\d+)\.(\d+)\b",
    ]
    for pat in patterns:
        m = re.search(pat, text.strip(), re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return None


def is_drupal_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str, List[str]]:
    """
    Return (is_vulnerable, fixed_version, matching_cves) for CVE-2026-136716 and CVE-2026-132165.
    """
    cves: List[str] = []
    fixed = "10.6.24 / 11.3.24 / 11.4.15"

    if version <= (10, 6, 23):
        fixed = "10.6.24"
        cves.append("CVE-2026-136716")
        if version <= (10, 6, 22):
            cves.append("CVE-2026-132165")
    elif (11, 0, 0) <= version <= (11, 3, 23):
        fixed = "11.3.24"
        cves.append("CVE-2026-136716")
        if version <= (11, 3, 22):
            cves.append("CVE-2026-132165")
    elif (11, 4, 0) <= version <= (11, 4, 14):
        fixed = "11.4.15"
        cves.append("CVE-2026-136716")
        if version <= (11, 4, 13):
            cves.append("CVE-2026-132165")

    return (len(cves) > 0, fixed, cves)


class DrupalCoreAuditPlugin(BasePlugin):
    name = "drupal_cve_2026_136716_audit"
    description = (
        "Passive version check for Drupal core access control and forceful browsing vulnerabilities "
        "(CVE-2026-136716, CVE-2026-132165, CVSS 9.8)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "drupal_cve_2026_136716_audit",
            "description": (
                "Passive version check for Drupal core access control and forceful browsing "
                "(CVE-2026-136716, CVE-2026-132165, CVSS 9.8)"
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-136716, CVE-2026-132165",
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

        for path in ("/core/CHANGELOG.txt", "/CHANGELOG.txt", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    x_gen = resp.headers.get("X-Generator", "")
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            for candidate in (x_gen, body):
                if path == "/" and "drupal" not in candidate.lower():
                    continue
                parsed = parse_drupal_version(candidate)
                if parsed:
                    ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                    evidence.append(f"Version extracted from {path}: {ver_str}")
                    return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("drupal_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied drupal_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(DRUPAL_CVES),
                "severity": "INFO",
                "finding": "Could not passively determine exact Drupal core patch version.",
                "remediation": "Upgrade Drupal core to 10.6.24, 11.3.24, or 11.4.15+.",
                "evidence": evidence,
            }

        parsed = parse_drupal_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(DRUPAL_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized Drupal core version format: '{raw_version}'.",
                "remediation": "Upgrade Drupal core to 10.6.24, 11.3.24, or 11.4.15+.",
                "evidence": evidence,
            }

        vuln, fixed, matched_cves = is_drupal_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": matched_cves,
                "severity": "CRITICAL",
                "cvss": 9.8,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Drupal core {ver_display} is vulnerable to {', '.join(matched_cves)} "
                    f"(fixed in {fixed})."
                ),
                "remediation": f"Upgrade Drupal core to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(DRUPAL_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Drupal core {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Drupal Core CVE-2026-136716 / CVE-2026-132165 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="drupal_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"drupal_version": args.drupal_version} if args.drupal_version else {}
    print(DrupalCoreAuditPlugin(args.target, opts).run_audit())
