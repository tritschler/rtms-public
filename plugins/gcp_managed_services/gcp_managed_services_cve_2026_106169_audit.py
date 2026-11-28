#!/usr/bin/env python3
"""
RTMS Audit Plugin — Google Cloud Platform Managed Services Revision Date Compliance Audit
Target CVEs:
  - CVE-2026-106169 (CVSS 9.4, Critical): Deserialization of Untrusted Data in Google Cloud
    Application Integration versions prior to 2026-09-22.
  - CVE-2026-85258 (CVSS 9.3, Critical): Missing Authorization in Google Cloud Vertex AI
    (Vertex AI Assistant) versions prior to 2026-04-13.
  - CVE-2026-110739 (CVSS 9.0, Critical): Incomplete List of Disallowed Inputs in Google Cloud
    GKE Fleet namespace onboarding API versions prior to 2026-09-25.

Strictly read-only passive revision-date compliance verification.
"""

import argparse
import re
from typing import Dict, List, Optional, Tuple

try:
    from core.plugin_base import BasePlugin
except ImportError:

    class BasePlugin:
        def __init__(self, target: str, options: Optional[Dict] = None):
            self.target = target
            self.options = options or {}


GCP_CVES: List[str] = ["CVE-2026-106169", "CVE-2026-85258", "CVE-2026-110739"]


def parse_gcp_revision_date(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a GCP service revision date string (e.g. '2026-09-20', '2026.09.25') into (year, month, day)."""
    if not text:
        return None
    m = re.search(r"\b(\d{4})[.\-](\d{2})[.\-](\d{2})\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_gcp_revision_vulnerable(rev_date: Tuple[int, int, int]) -> Tuple[bool, str, List[str]]:
    """
    Return (is_vulnerable, fixed_revision, matching_cves) across:
      - CVE-2026-85258 (< 2026-04-13)
      - CVE-2026-106169 (< 2026-09-22)
      - CVE-2026-110739 (< 2026-09-25)
    """
    cves: List[str] = []
    if rev_date < (2026, 4, 13):
        cves.append("CVE-2026-85258")
    if rev_date < (2026, 9, 22):
        cves.append("CVE-2026-106169")
    if rev_date < (2026, 9, 25):
        cves.append("CVE-2026-110739")
    return (len(cves) > 0, "2026-09-25", cves)


class GCPManagedServicesAuditPlugin(BasePlugin):
    name = "gcp_managed_services_cve_2026_106169_audit"
    description = (
        "Passive revision-date compliance audit for Google Cloud Application Integration, Vertex AI, "
        "and GKE Fleet (CVE-2026-106169, CVE-2026-85258, CVE-2026-110739, CVSS 9.4)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "gcp_managed_services_cve_2026_106169_audit",
            "description": (
                "Passive revision-date compliance audit for Google Cloud Application Integration, Vertex AI, "
                "and GKE Fleet (CVE-2026-106169, CVE-2026-85258, CVE-2026-110739, CVSS 9.4)"
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-106169, CVE-2026-85258, CVE-2026-110739",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        raw_version = self.options.get("revision_date")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied revision_date option: {raw_version}")
        else:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(GCP_CVES),
                "severity": "INFO",
                "finding": "No GCP service revision date supplied for compliance verification.",
                "remediation": "Verify GCP control-plane revision is at or above 2026-09-25.",
                "evidence": evidence,
            }

        parsed = parse_gcp_revision_date(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": list(GCP_CVES),
                "severity": "INFO",
                "finding": f"Unrecognized GCP revision date format: '{raw_version}'.",
                "remediation": "Verify GCP control-plane revision is at or above 2026-09-25.",
                "evidence": evidence,
            }

        vuln, fixed, matched_cves = is_gcp_revision_vulnerable(parsed)
        ver_display = f"{parsed[0]:04d}-{parsed[1]:02d}-{parsed[2]:02d}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": matched_cves,
                "severity": "CRITICAL",
                "cvss": 9.4,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"GCP service revision {ver_display} predates provider patch levels for "
                    f"{', '.join(matched_cves)} (fixed by {fixed})."
                ),
                "remediation": f"Ensure GCP service plane is updated to revision {fixed} or later.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": list(GCP_CVES),
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"GCP service revision {ver_display} is at or above patched level {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GCP Managed Services CVE-2026-106169 / 85258 / 110739 Passive Audit")
    parser.add_argument("--target", required=True, help="Target GCP project or endpoint identifier")
    parser.add_argument("--version", dest="revision_date", help="Service revision date (YYYY-MM-DD)")
    args = parser.parse_args()
    opts = {"revision_date": args.revision_date} if args.revision_date else {}
    print(GCPManagedServicesAuditPlugin(args.target, opts).run_audit())
