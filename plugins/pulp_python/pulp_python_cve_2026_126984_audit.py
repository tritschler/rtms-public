#!/usr/bin/env python3
"""
RTMS Audit Plugin — Pulp pulp_python Pull-Through Caching SSRF Audit
Target CVE:
  - CVE-2026-126984 (CVSS 10.0, Critical): Server-Side Request Forgery (SSRF) in
    get_remote_artifact_url() in pulp_python/app/models.py of the pull-through caching feature.

Affected versions:
  - 3.6.0 <= v < 3.11.10
  - 3.12.0 <= v < 3.12.11
  - 3.13.0 <= v < 3.13.9
  - 3.14.0 <= v < 3.19.8
  - 3.20.0 <= v < 3.27.10
  - 3.28.0 <= v < 3.36.7
  - 3.37.0 <= v < 3.38.2

Strictly read-only passive version check via Pulp `/pulp/api/v3/status/` endpoint or supplied version string.
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


def parse_pulp_python_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a pulp_python version string (e.g. '3.38.1', '3.38.2') into (major, minor, patch)."""
    if not text:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", text.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_pulp_python_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-126984."""
    if (3, 6, 0) <= version < (3, 11, 10):
        return True, "3.11.10"
    if (3, 12, 0) <= version < (3, 12, 11):
        return True, "3.12.11"
    if (3, 13, 0) <= version < (3, 13, 9):
        return True, "3.13.9"
    if (3, 14, 0) <= version < (3, 19, 8):
        return True, "3.19.8"
    if (3, 20, 0) <= version < (3, 27, 10):
        return True, "3.27.10"
    if (3, 28, 0) <= version < (3, 36, 7):
        return True, "3.36.7"
    if (3, 37, 0) <= version < (3, 38, 2):
        return True, "3.38.2"
    return False, "3.38.2"


class PulpPythonAuditPlugin(BasePlugin):
    name = "pulp_python_cve_2026_126984_audit"
    description = (
        "Passive version check for Pulp pulp_python pull-through caching SSRF "
        "(CVE-2026-126984, CVSS 10.0)"
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

        url = f"{base_url}/pulp/api/v3/status/"
        req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(65536).decode("utf-8", errors="ignore")
                m = re.search(
                    r'"component"\s*:\s*"(?:python|pulp_python)"[^}]*"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
                    body,
                    re.IGNORECASE,
                )
                if m:
                    ver = m.group(1)
                    evidence.append(f"pulp_python version extracted from /pulp/api/v3/status/: {ver}")
                    return ver, evidence
        except Exception as e:
            evidence.append(f"HTTP probe {url} failed: {e}")
        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("pulp_python_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied pulp_python_version option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-126984"],
                "severity": "INFO",
                "finding": "Could not passively determine pulp_python version.",
                "remediation": "Upgrade pulp_python to 3.38.2, 3.36.7, 3.27.10, 3.19.8, 3.13.9, 3.12.11, or 3.11.10+.",
                "evidence": evidence,
            }

        parsed = parse_pulp_python_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-126984"],
                "severity": "INFO",
                "finding": f"Unrecognized pulp_python version format: '{raw_version}'.",
                "remediation": "Upgrade pulp_python to 3.38.2 or the corresponding patched branch release.",
                "evidence": evidence,
            }

        vuln, fixed = is_pulp_python_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-126984"],
                "severity": "CRITICAL",
                "cvss": 10.0,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"pulp_python {ver_display} is vulnerable to CVE-2026-126984 "
                    f"(pull-through caching SSRF in get_remote_artifact_url(), fixed in {fixed})."
                ),
                "remediation": f"Upgrade pulp_python to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-126984"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"pulp_python {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pulp pulp_python CVE-2026-126984 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="pulp_python_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"pulp_python_version": args.pulp_python_version} if args.pulp_python_version else {}
    print(PulpPythonAuditPlugin(args.target, opts).run_audit())
