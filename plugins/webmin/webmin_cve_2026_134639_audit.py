#!/usr/bin/env python3
"""
RTMS Audit Plugin — Webmin Insecure Default Administrative Provisioning
Target CVE:
  - CVE-2026-134639 (CVSS 9.2, Critical): Insecure default administrative account
    provisioning and credential handling in Webmin <= 2.670 allowing remote
    unauthenticated privilege escalation or unauthorized root console takeover.

Affected versions:
  - Webmin <= 2.670 (patched in 2.671)

Strictly read-only passive version check via MiniServ HTTP Server header or Webmin
login banner on default port 10000. No login attempts are made.
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


def parse_webmin_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a Webmin version string (e.g. '2.670', '2.671', 'MiniServ/2.620')
    into a (major, minor, patch) tuple.
    """
    if not version_str:
        return None
    m = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b", version_str.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def is_webmin_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """
    Return (is_vulnerable, fixed_version) for CVE-2026-134639.
    Affected: <= 2.670 (i.e. < (2, 671, 0)).
    """
    if version <= (2, 670, 999):
        return True, "2.671"
    return False, "2.671"


class WebminAuditPlugin(BasePlugin):
    name = "webmin_cve_2026_134639_audit"
    description = (
        "Passive version check for Webmin insecure default administrative provisioning "
        "(CVE-2026-134639, CVSS 9.2)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 10000))
        scheme = "https" if self.options.get("ssl", True) else "http"
        if ":" in t:
            return f"{scheme}://{t}"
        return f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        patterns = [
            re.compile(r"MiniServ/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
            re.compile(r"Webmin\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        ]

        url = f"{base_url}/"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "RTMS-Compliance-Audit/1.0"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read(65536).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            try:
                body = e.read(65536).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        except Exception as e:
            evidence.append(f"HTTP probe {url} failed: {e}")
            return None, evidence

        srv = headers.get("server") or ""
        for pat in patterns:
            m = pat.search(srv)
            if m:
                ver = m.group(1)
                evidence.append(f"Version extracted from Server header ('{srv}'): {ver}")
                return ver, evidence

        for pat in patterns:
            m = pat.search(body)
            if m:
                ver = m.group(1)
                evidence.append(f"Version extracted from HTTP body: {ver}")
                return ver, evidence

        return None, evidence

    def run_audit(self) -> Dict:
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("webmin_version")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied webmin_version option: {raw_version}")
        else:
            base_url = self._build_base_url()
            raw_version, probe_ev = self._probe_version(base_url, timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-134639"],
                "severity": "INFO",
                "finding": "Could not passively determine Webmin / MiniServ version.",
                "remediation": "Verify Webmin version manually and upgrade to 2.671 or later.",
                "evidence": evidence,
            }

        parsed = parse_webmin_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-134639"],
                "severity": "INFO",
                "finding": f"Unrecognized Webmin version format: '{raw_version}'.",
                "remediation": "Upgrade Webmin to 2.671 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_webmin_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}" if parsed[2] == 0 else f"{parsed[0]}.{parsed[1]}.{parsed[2]}"

        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-134639"],
                "severity": "CRITICAL",
                "cvss": 9.2,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"Webmin {ver_display} is vulnerable to CVE-2026-134639 "
                    f"(insecure default admin provisioning, fixed in {fixed})."
                ),
                "remediation": f"Upgrade Webmin to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-134639"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"Webmin {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Webmin CVE-2026-134639 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="webmin_version", help="Override detected version string")
    args = parser.parse_args()

    opts = {}
    if args.webmin_version:
        opts["webmin_version"] = args.webmin_version
    plugin = WebminAuditPlugin(args.target, opts)
    print(plugin.run_audit())
