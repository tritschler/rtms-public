#!/usr/bin/env python3
"""
RTMS Audit Plugin — MONEO ERP WebSocket JSON-RPC Session Authentication Bypass Audit
Target CVE:
  - CVE-2026-59103 (CVSS 9.3, Critical): MONEO ERP exposes the Ping method of its _slave
    JSON-RPC service over WebSocket as @rpc.openpublic without requiring a valid session,
    allowing unauthenticated session creation via client-controlled parameters.

Strictly read-only passive version/build compliance check for MONEO ERP instances.
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


def parse_moneo_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a MONEO ERP version/date string (e.g. '2026.11.20', '2026-11-28', '8.4.1') into (v1, v2, v3)."""
    if not text:
        return None
    m = re.search(r"\b(\d{4})[.\-](\d{1,2})[.\-](\d{1,2})\b|\bv?(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    if m.group(1):
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (int(m.group(4)), int(m.group(5)), int(m.group(6) or 0))


def is_moneo_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-59103 (< 2026.11.28 security patch)."""
    if version < (2026, 11, 28):
        return True, "2026.11.28"
    return False, "2026.11.28"


class MoneoERPAuditPlugin(BasePlugin):
    name = "moneo_erp_cve_2026_59103_audit"
    description = (
        "Passive version check for MONEO ERP WebSocket JSON-RPC session authentication bypass "
        "(CVE-2026-59103, CVSS 9.3)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "moneo_erp_cve_2026_59103_audit",
            "description": (
                "Passive version check for MONEO ERP WebSocket JSON-RPC session authentication bypass "
                "(CVE-2026-59103, CVSS 9.3)"
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-59103",
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

        for path in ("/version", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            if "moneo" not in body.lower():
                continue
            parsed = parse_moneo_version(body)
            if parsed:
                ver_str = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
                evidence.append(f"Version extracted from {path}: {ver_str}")
                return ver_str, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("moneo_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied moneo_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-59103"],
                "severity": "INFO",
                "finding": "Could not passively determine MONEO ERP build/version.",
                "remediation": "Apply the MONEO ERP security update addressing CVE-2026-59103 (2026.11.28+).",
                "evidence": evidence,
            }

        parsed = parse_moneo_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-59103"],
                "severity": "INFO",
                "finding": f"Unrecognized MONEO ERP version format: '{raw_version}'.",
                "remediation": "Apply the MONEO ERP security update addressing CVE-2026-59103 (2026.11.28+).",
                "evidence": evidence,
            }

        vuln, fixed = is_moneo_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-59103"],
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"MONEO ERP {ver_display} is vulnerable to CVE-2026-59103 "
                    f"(unauthenticated WebSocket JSON-RPC session creation)."
                ),
                "remediation": f"Upgrade MONEO ERP to build {fixed} or later and restrict external WebSocket RPC access.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-59103"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"MONEO ERP {ver_display} is at or above patched build {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MONEO ERP CVE-2026-59103 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="moneo_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"moneo_version": args.moneo_version} if args.moneo_version else {}
    print(MoneoERPAuditPlugin(args.target, opts).run_audit())
