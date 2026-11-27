#!/usr/bin/env python3
"""
RTMS Audit Plugin — llama.cpp ggml RPC Server Heap Out-of-Bounds Write Audit
Target CVE:
  - CVE-2026-137567 (CVSS 9.3, Critical): llama.cpp b11450 before b12658 contains an out-of-bounds
    write vulnerability in the ggml RPC server allowing unauthenticated attackers to write to arbitrary
    heap addresses via zero-element destination tensors.

Strictly read-only passive version check via llama.cpp HTTP `/props` or `/health` metadata or supplied build string.
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


def parse_llama_cpp_build(text: str) -> Optional[int]:
    """Parse a llama.cpp build version string (e.g. 'b12000', 'b12658', '12500') into an integer build number."""
    if not text:
        return None
    m = re.search(r"\bb?(\d{4,6})\b", text.strip(), re.IGNORECASE)
    if not m:
        return None
    return int(m.group(1))


def is_llama_cpp_build_vulnerable(build_num: int) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_build) for CVE-2026-137567 (b11450 <= build < b12658)."""
    if 11450 <= build_num < 12658:
        return True, "b12658"
    return False, "b12658"


class LlamaCppAuditPlugin(BasePlugin):
    name = "llama_cpp_cve_2026_137567_audit"
    description = (
        "Passive version check for llama.cpp ggml RPC server heap out-of-bounds write "
        "(CVE-2026-137567, CVSS 9.3)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "llama_cpp_cve_2026_137567_audit",
            "description": "Passive version check for llama.cpp ggml RPC server heap out-of-bounds write (CVE-2026-137567, CVSS 9.3)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-137567",
            "version": "1.0.0",
        }

    def check_requirements(self, target_ip: str = "", target_services: object = None) -> bool:
        return True

    def _build_base_url(self) -> str:
        t = self.target.strip().rstrip("/")
        if t.startswith("http://") or t.startswith("https://"):
            return t
        port = int(self.options.get("port", 8080))
        scheme = "https" if port in (443, 8443) or self.options.get("ssl", False) else "http"
        return f"{scheme}://{t}" if ":" in t else f"{scheme}://{t}:{port}"

    def _probe_version(self, base_url: str, timeout: int) -> Tuple[Optional[str], List[str]]:
        evidence: List[str] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for path in ("/props", "/health"):
            url = f"{base_url}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "RTMS-Compliance-Audit/1.0"}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(65536).decode("utf-8", errors="ignore")
            except Exception as e:
                evidence.append(f"HTTP probe {url} failed: {e}")
                continue

            m = re.search(r"\b(b\d{4,6})\b", body, re.IGNORECASE)
            if m:
                ver = m.group(1)
                evidence.append(f"Build extracted from {path}: {ver}")
                return ver, evidence
        return None, evidence

    def run_audit(self, target_ip: str = "", target_services: object = None, credentials: object = None) -> Dict:
        if target_ip and not getattr(self, "target", ""):
            self.target = target_ip
        timeout = int(self.options.get("timeout", 8))
        raw_version = self.options.get("llama_build")
        evidence: List[str] = []

        if raw_version:
            evidence.append(f"Using supplied llama_build option: {raw_version}")
        else:
            raw_version, probe_ev = self._probe_version(self._build_base_url(), timeout)
            evidence.extend(probe_ev)

        if not raw_version:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137567"],
                "severity": "INFO",
                "finding": "Could not passively determine llama.cpp build version.",
                "remediation": "Upgrade llama.cpp to build b12658 or later and restrict ggml RPC server network exposure.",
                "evidence": evidence,
            }

        build_num = parse_llama_cpp_build(str(raw_version))
        if build_num is None:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-137567"],
                "severity": "INFO",
                "finding": f"Unrecognized llama.cpp build format: '{raw_version}'.",
                "remediation": "Upgrade llama.cpp to build b12658 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_llama_cpp_build_vulnerable(build_num)
        ver_display = f"b{build_num}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-137567"],
                "severity": "CRITICAL",
                "cvss": 9.3,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"llama.cpp {ver_display} is vulnerable to CVE-2026-137567 "
                    f"(ggml RPC server heap out-of-bounds write, fixed in {fixed})."
                ),
                "remediation": f"Upgrade llama.cpp to build {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-137567"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"llama.cpp {ver_display} is outside the vulnerable range or >= {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="llama.cpp CVE-2026-137567 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="llama_build", help="Override detected build string")
    args = parser.parse_args()
    opts = {"llama_build": args.llama_build} if args.llama_build else {}
    print(LlamaCppAuditPlugin(args.target, opts).run_audit())
