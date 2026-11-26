#!/usr/bin/env python3
"""
RTMS Audit Plugin — Camunda 8 Persistent Web Session Deserialization RCE
Target CVE:
  - CVE-2026-77230 (CVSS 9.2, Critical): Insecure Java deserialization in Camunda 8
    persistent web session storage (Operate / Tasklist / Identity / Zeebe Webapps),
    allowing remote attackers to execute arbitrary code.

Affected versions:
  - Camunda 8.8.0 <= version < 8.8.47 (patched in 8.8.47)
  - Camunda 8.9.0 <= version < 8.9.29 (patched in 8.9.29)
  - Camunda 8.10.0 <= version < 8.10.10 (patched in 8.10.10)
  - Camunda 8.11.0-alpha1 (patched in 8.11.0-alpha2 / 8.11.0)

Strictly read-only passive version check via Camunda Actuator info or web UI assets.
No serialized objects or session payloads are transmitted.
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


def parse_camunda_version(version_str: str) -> Optional[Tuple[int, int, int, int]]:
    """
    Parse a Camunda 8 version string (e.g. '8.9.14', '8.10.9', '8.11.0-alpha1')
    into (major, minor, patch, alpha_num) where alpha_num is 9999 for stable releases.
    """
    if not version_str:
        return None
    m = re.search(
        r"\b(8)\.(\d+)\.(\d+)(?:-alpha(\d+))?\b",
        version_str.strip(),
        re.IGNORECASE,
    )
    if not m:
        return None
    alpha = int(m.group(4)) if m.group(4) is not None else 9999
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), alpha)


def is_camunda_version_vulnerable(version: Tuple[int, int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-77230.
    """
    major, minor, patch, alpha = version
    if major != 8:
        return False, "8.10.10"
    if minor == 8 and (patch, alpha) < (47, 9999):
        return True, "8.8.47"
    if minor == 9 and (patch, alpha) < (29, 9999):
        return True, "8.9.29"
    if minor == 10 and (patch, alpha) < (10, 9999):
        return True, "8.10.10"
    if minor == 11 and patch == 0 and alpha == 1:
        return True, "8.11.0"
    return False, "8.10.10"


class CamundaAuditPlugin(BasePlugin):
    name = "camunda_cve_2026_77230_audit"
    description = (
        "Passive version check for Camunda 8 persistent web session deserialization RCE "
        "(CVE-2026-77230, CVSS 9.2)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 8080))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        if ":" in t:
            return f"{scheme}://{t}"
        return f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        patterns = [
            re.compile(r'"version"\s*:\s*"(8\.\d+\.\d+(?:-alpha\d+)?)"', re.IGNORECASE),
            re.compile(r"Camunda[^0-9]{0,25}v?(8\.\d+\.\d+(?:-alpha\d+)?)", re.IGNORECASE),
        ]

        for path in ("/actuator/info", "/v2/status", "/login", "/"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "RTMS-Compliance-Audit/1.0", "Accept": "application/json,text/html"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as e:
                try:
                    body = e.read(65536).decode("utf-8", errors="ignore")
                except Exception:
                    body = ""
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            for pat in patterns:
                m = pat.search(body)
                if m:
                    ver = m.group(1)
                    evidence.append(f"Version extracted from {path}: {ver}")
                    return ver, evidence

        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("camunda_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied camunda_version option: {raw_version}")
        else:
            base_url = self._build_base_url()
            raw_version, probe_ev = self._probe_version(base_url, timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-77230"],
                "severity": "INFO",
                "finding": "Could not passively determine Camunda 8 version.",
                "remediation": (
                    "Verify Camunda 8 version manually and upgrade to 8.8.47, 8.9.29, or 8.10.10+."
                ),
                "evidence": evidence,
            }

        parsed = parse_camunda_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-77230"],
                "severity": "INFO",
                "finding": f"Unrecognized Camunda 8 version format: '{raw_version}'.",
                "remediation": "Upgrade Camunda 8 to 8.8.47, 8.9.29, or 8.10.10+.",
                "evidence": evidence,
            }

        vuln, fixed = is_camunda_version_vulnerable(parsed)
        suffix = f"-alpha{parsed[3]}" if parsed[3] != 9999 else ""
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}{suffix}"

        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-77230"],
                "severity": "CRITICAL",
                "cvss": 9.2,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Camunda {ver_display} is vulnerable to CVE-2026-77230 "
                    f"(persistent web session deserialization RCE, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Camunda 8 to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-77230"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Camunda {ver_display} is not within an affected version range.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Camunda 8 CVE-2026-77230 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="camunda_version", help="Override detected version string")
    args = parser.parse_args()

    opts = {}
    if args.camunda_version:
        opts["camunda_version"] = args.camunda_version
    plugin = CamundaAuditPlugin(args.target, opts)
    print(plugin.run_audit())
