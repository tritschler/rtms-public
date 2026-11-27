#!/usr/bin/env python3
"""
RTMS Audit Plugin — WordPress PDF Invoice for WooCommerce PHP Object Injection Audit
Target CVE:
  - CVE-2026-136240 (CVSS 9.1, Critical): PHP Object Injection in PDF Invoice for WooCommerce +
    Drag and Drop Template Builder <= 7.2.0 via deserialization of untrusted input.

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


def parse_pdf_invoice_wc_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Parse a PDF Invoice for WooCommerce version string (e.g. '7.2.0', '7.2.1') into (major, minor, patch)."""
    if not text:
        return None
    patterns = [
        r"/wp-content/plugins/(?:pdf-invoice-for-woocommerce|woo-pdf-invoice-builder)/[^\"'\s>]+?\?ver=(\d+)\.(\d+)(?:\.(\d+))?",
        r"(?:Stable\s+tag|Version)\s*:\s*(\d+)\.(\d+)(?:\.(\d+))?",
        r"\b(\d+)\.(\d+)(?:\.(\d+))?\b",
    ]
    for pat in patterns:
        m = re.search(pat, text.strip(), re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return None


def is_pdf_invoice_wc_version_vulnerable(version: Tuple[int, int, int]) -> Tuple[bool, str]:
    """Return (is_vulnerable, fixed_version) for CVE-2026-136240 (<= 7.2.0)."""
    if version <= (7, 2, 0):
        return True, "7.2.1"
    return False, "7.2.1"


class WPPDFInvoiceWooCommerceAuditPlugin(BasePlugin):
    name = "wp_pdf_invoice_woocommerce_cve_2026_136240_audit"
    description = (
        "Passive version check for WordPress PDF Invoice for WooCommerce PHP Object Injection "
        "(CVE-2026-136240, CVSS 9.1)"
    )
    author = "RTMS Security Team"
    version = "1.0.0"

    def __init__(self, target: str = "", options: Optional[Dict] = None):
        self.target = target
        self.options = options or {}
        self.info = {
            "name": "wp_pdf_invoice_woocommerce_cve_2026_136240_audit",
            "description": "Passive version check for WordPress PDF Invoice for WooCommerce PHP Object Injection (CVE-2026-136240, CVSS 9.1)",
            "severity": "CRITICAL",
            "cve": "CVE-2026-136240",
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
            "/wp-content/plugins/pdf-invoice-for-woocommerce/readme.txt",
            "/wp-content/plugins/woo-pdf-invoice-builder/readme.txt",
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

            if path == "/" and "pdf-invoice" not in body.lower():
                continue
            parsed = parse_pdf_invoice_wc_version(body)
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
                "cve": ["CVE-2026-136240"],
                "severity": "INFO",
                "finding": "Could not passively determine PDF Invoice for WooCommerce plugin version.",
                "remediation": "Ensure PDF Invoice for WooCommerce is updated to 7.2.1 or later.",
                "evidence": evidence,
            }

        parsed = parse_pdf_invoice_wc_version(str(raw_version))
        if not parsed:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Inconclusive",
                "cve": ["CVE-2026-136240"],
                "severity": "INFO",
                "finding": f"Unrecognized PDF Invoice for WooCommerce version format: '{raw_version}'.",
                "remediation": "Update PDF Invoice for WooCommerce to 7.2.1 or later.",
                "evidence": evidence,
            }

        vuln, fixed = is_pdf_invoice_wc_version_vulnerable(parsed)
        ver_display = f"{parsed[0]}.{parsed[1]}.{parsed[2]}"
        if vuln:
            return {
                "plugin": self.name,
                "target": self.target,
                "status": "Vulnerable",
                "cve": ["CVE-2026-136240"],
                "severity": "CRITICAL",
                "cvss": 9.1,
                "detected_version": ver_display,
                "fixed_version": fixed,
                "finding": (
                    f"PDF Invoice for WooCommerce {ver_display} is vulnerable to CVE-2026-136240 "
                    f"(PHP Object Injection via deserialization, <= 7.2.0)."
                ),
                "remediation": f"Upgrade PDF Invoice for WooCommerce to version {fixed} or later immediately.",
                "evidence": evidence,
            }

        return {
            "plugin": self.name,
            "target": self.target,
            "status": "OK",
            "cve": ["CVE-2026-136240"],
            "severity": "NONE",
            "detected_version": ver_display,
            "fixed_version": fixed,
            "finding": f"PDF Invoice for WooCommerce {ver_display} is at or above patched version {fixed}.",
            "remediation": "No action required.",
            "evidence": evidence,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WordPress PDF Invoice for WooCommerce CVE-2026-136240 Passive Audit")
    parser.add_argument("--target", required=True, help="Target URL or hostname")
    parser.add_argument("--version", dest="plugin_version", help="Override detected version string")
    args = parser.parse_args()
    opts = {"plugin_version": args.plugin_version} if args.plugin_version else {}
    print(WPPDFInvoiceWooCommerceAuditPlugin(args.target, opts).run_audit())
