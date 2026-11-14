"""
wp_advance_guest_post_cve_2026_118063_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for WordPress installations
running the Advance Guest Post plugin (<= 1.9 (< 1.9.1)) to verify patch compliance
for CVE-2026-118063, CVE-2026-118064.

CVSS Score: 9.8 (Critical)
Affected Components: WordPress Advance Guest Post Plugin (<= 1.9 (< 1.9.1)).
Fixed in: Advance Guest Post 1.9.1+.

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import socket
import ssl
import http.client
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

try:
    from base_plugin import BasePlugin
except ImportError:
    class BasePlugin:  # type: ignore
        def __init__(self):
            self.info: Dict[str, Any] = {}

        def format_result(self, status: str, proof: str = "", details: str = "") -> Dict[str, Any]:
            return {
                "plugin": self.info.get("name", "Unknown"),
                "severity": self.info.get("severity", "Info"),
                "status": status,
                "proof": proof,
                "details": details,
            }

        def execute(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
            if hasattr(self, "check_requirements") and not self.check_requirements(target_ip, target_services):
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/HTTPS services found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8088, 8888, 9443]
SSL_PORTS = {443, 8443, 9443, 4433, 10443}
MIN_PATCHED_VERSION = (1, 9, 1)


def parse_advance_guest_post_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Advance Guest Post semantic version (major, minor, patch, raw_str) from:
      - WordPress asset query strings: /wp-content/plugins/advance-guest-post/...?ver=X.Y.Z
      - Plugin readme headers: 'Stable tag: X.Y.Z', 'Version: X.Y.Z'
      - Changelog headings: '= X.Y.Z ='
    """
    if not text:
        return None

    patterns = [
        r"/wp-content/plugins/(?:advance-guest-post|advance-guest-post)/[^\"'\s>]+?\?ver=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"(?:Stable\s+tag|Version|\*+\s*Version)\s*:\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"(?:=+|###)\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\s*(?:=+|\||-|$)",
        r"^v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            raw_ver = f"{major}.{minor}.{patch}"
            return major, minor, patch, raw_ver

    return None


def is_advance_guest_post_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Advance Guest Post version tuple is affected by CVE-2026-118063, CVE-2026-118064 (<= 1.9 (< 1.9.1)).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if ver_tuple < MIN_PATCHED_VERSION:
        return True, (
            f"Advance Guest Post {ver_str} is affected by CVE-2026-118063, CVE-2026-118064 "
            f"(affected: <= 1.9 (< 1.9.1); requires upgrade to >= 1.9.1)."
        )

    return False, (
        f"Advance Guest Post {ver_str} is patched against CVE-2026-118063, CVE-2026-118064 "
        f"(running >= 1.9.1)."
    )


class WPAdvanceGuestPostAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: WordPress Advance Guest Post File Upload Validation Audit (CVE-2026-118063, CVE-2026-118064).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "WordPress Advance Guest Post File Upload Validation Audit (CVE-2026-118063)",
            "description": (
                "Passive version compliance check for WordPress Advance Guest Post <= 1.9 (< 1.9.1) "
                "(CVE-2026-118063, CVE-2026-118064 - CVSS 9.8)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-118063, CVE-2026-118064",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_WEB_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        self.discovered_ports = []

        if isinstance(target_services, dict):
            for port_raw, s_info in target_services.items():
                try:
                    port = int(port_raw)
                except (ValueError, TypeError):
                    continue

                s_name = ""
                if isinstance(s_info, dict):
                    s_name = str(s_info.get("name") or s_info.get("service") or "").lower()
                elif isinstance(s_info, str):
                    s_name = s_info.lower()

                if (
                    port in self.target_ports
                    or "http" in s_name
                    or "web" in s_name
                    or "wordpress" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/",
        timeout: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        use_ssl = port in SSL_PORTS
        conn = None

        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target_ip, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target_ip, port=port, timeout=timeout)

            headers = {
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-118063)",
                "Accept": "text/html,text/plain,application/json,*/*",
                "Connection": "close",
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            raw_body = response.read(32768).decode("utf-8", errors="replace")

            resp_headers: Dict[str, str] = {}
            for k, v in response.getheaders():
                resp_headers[k.lower()] = v

            return {
                "port": port,
                "path": path,
                "status_code": response.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:16384],
            }
        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        root_probe = self.probe_http_endpoint(target_ip, port, path="/", timeout=timeout)
        if not root_probe:
            return None

        root_body = root_probe.get("body_snippet", "")
        ver_from_html = parse_advance_guest_post_version(root_body)
        if ver_from_html and ("advance-guest-post" in root_body.lower() or "advance-guest-post" in root_body.lower()):
            major, minor, patch, ver_str = ver_from_html
            is_vuln, reason = is_advance_guest_post_version_vulnerable(major, minor, patch)
            return {
                "port": port,
                "plugin_detected": True,
                "version": ver_str,
                "source": "HTML asset reference (/wp-content/plugins/advance-guest-post/...?ver=)",
                "is_vulnerable": is_vuln,
                "reason": reason,
            }

        readme_probe = self.probe_http_endpoint(
            target_ip, port, path="/wp-content/plugins/advance-guest-post/readme.txt", timeout=timeout
        )
        if readme_probe and readme_probe.get("status_code") == 200:
            body = readme_probe.get("body_snippet", "")
            ver_info = parse_advance_guest_post_version(body)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_advance_guest_post_version_vulnerable(major, minor, patch)
                return {
                    "port": port,
                    "plugin_detected": True,
                    "version": ver_str,
                    "source": "Advance Guest Post readme.txt",
                    "is_vulnerable": is_vuln,
                    "reason": reason,
                }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("plugin_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Advance Guest Post {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Advance Guest Post {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-118063, CVE-2026-118064 unpatched version detected on {target_ip}.\n"
                f"Affected WordPress Advance Guest Post endpoints:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-118063, CVE-2026-118064 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an outdated version of the WordPress Advance Guest Post plugin (<= 1.9 (< 1.9.1)).\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-118063, CVE-2026-118064: Improper file upload validation and extension check bypass in the Advance Guest Post WordPress plugin.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Update the Advance Guest Post WordPress plugin to version 1.9.1 or later."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: WordPress Advance Guest Post instances on {target_ip} are running patched versions "
                f"(>= 1.9.1) compliant against CVE-2026-118063, CVE-2026-118064:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected WordPress Advance Guest Post installations detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version audit for WordPress Advance Guest Post (CVE-2026-118063, CVE-2026-118064)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[80, 443, 8080, 8443])
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    plugin = WPAdvanceGuestPostAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        sys.exit(0)
    res = plugin.run_audit(args.target, args.ports)
    if res.get("status") == "Vulnerable":
        print(res.get("details", ""))
        sys.exit(1)
    print(res.get("details", ""))
    sys.exit(0)
