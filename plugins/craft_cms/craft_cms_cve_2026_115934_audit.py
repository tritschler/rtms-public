"""
craft_cms_cve_2026_115934_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for Craft CMS
deployments to check patch compliance for CVE-2026-115934.

CVSS Score: 9.3 (Critical) - CWE-89 (Improper Neutralization of Special Elements in SQL Command)
Affected Components: Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2.
Fixed in: Craft CMS 4.18.9+ and 5.11.2+.

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

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 3000]
SSL_PORTS = {443, 8443, 9443}

MIN_PATCHED_V4 = (4, 18, 9)
MIN_PATCHED_V5 = (5, 11, 2)


def parse_craft_cms_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Craft CMS semantic version (major, minor, patch, raw_str) from:
      - HTTP X-Powered-By header: 'Craft CMS 4.18.5' or 'Craft CMS/5.11.0'
      - HTML meta generator tag or login page config: 'Craft CMS 5.10.2', '"version":"4.18.8"'
    """
    if not text:
        return None

    patterns = [
        r"Craft\s*CMS[/\s:v]+([0-9]+)\.([0-9]+)\.([0-9]+)",
        r"[\"'](?:craftVersion|systemVersion|version)[\"']\s*:\s*[\"']v?([0-9]+)\.([0-9]+)\.([0-9]+)",
        r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            raw_ver = f"{major}.{minor}.{patch}"
            return major, minor, patch, raw_ver

    return None


def is_craft_cms_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Craft CMS version tuple (major, minor, patch) is affected by
    CVE-2026-115934:
      - 4.0.0 <= version < 4.18.9
      - 5.0.0 <= version < 5.11.2
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if major == 4 and (4, 0, 0) <= ver_tuple < MIN_PATCHED_V4:
        return True, (
            f"Craft CMS {ver_str} is affected by CVE-2026-115934 "
            f"(affected 4.x branch: 4.0.0 before 4.18.9; requires upgrade to >= 4.18.9)."
        )

    if major == 5 and (5, 0, 0) <= ver_tuple < MIN_PATCHED_V5:
        return True, (
            f"Craft CMS {ver_str} is affected by CVE-2026-115934 "
            f"(affected 5.x branch: 5.0.0 before 5.11.2; requires upgrade to >= 5.11.2)."
        )

    return False, (
        f"Craft CMS {ver_str} is not affected by CVE-2026-115934 "
        f"(patched in >= 4.18.9 and >= 5.11.2)."
    )


class CraftCmsAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Craft CMS Version Compliance Audit (CVE-2026-115934).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Craft CMS Version Compliance Audit (CVE-2026-115934)",
            "description": (
                "Passive version compliance check for Craft CMS 4.0.0 before 4.18.9 "
                "and 5.0.0 before 5.11.2 (CVE-2026-115934)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-115934",
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
                    or "craft" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
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
        use_ssl = port in SSL_PORTS or port in (443, 8443, 9443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-115934)",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                "Connection": "close",
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            raw_body = response.read(16384).decode("utf-8", errors="replace")

            resp_headers: Dict[str, str] = {}
            for k, v in response.getheaders():
                resp_headers[k.lower()] = v

            return {
                "port": port,
                "path": path,
                "status_code": response.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:8192],
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
        candidate_paths = [
            ("/admin/login", "Craft CMS /admin/login endpoint"),
            ("/", "Craft CMS front-end root page"),
        ]

        craft_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            powered_by = headers.get("x-powered-by", "")
            cookies = headers.get("set-cookie", "")
            combined = f"{powered_by}\n{cookies}\n{body}"
            combined_lower = combined.lower()

            if (
                "craft cms" in combined_lower
                or "craftsessionid" in combined_lower
                or "craft_csrf_token" in combined_lower
                or "/cpresources/" in combined_lower
            ):
                craft_detected = True
                detected_source = f"{source_label} (headers / page metadata)"

                ver_info = parse_craft_cms_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_craft_cms_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if craft_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Craft CMS installation detected on this endpoint, but exact version metadata is "
                    "concealed. Verify in the Craft Control Panel (Utilities > System Report) that "
                    "Craft CMS is updated to >= 4.18.9 or >= 5.11.2."
                ),
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        safe_findings: List[str] = []
        concealed_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("service_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Craft CMS {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Craft CMS {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-115934 affected Craft CMS version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-115934 - CVSS 9.3):\n"
                f"The target host {target_ip} runs an affected version of Craft CMS (< 4.18.9 or < 5.11.2).\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Update Craft CMS immediately to version 4.18.9+ (for 4.x) or 5.11.2+ (for 5.x).\n"
                f"2. Ensure `sendPoweredByHeader` is disabled in Craft general configuration to minimize banner exposure."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Craft CMS detected with concealed version string."
            details = (
                f"Craft CMS detected on {target_ip}, but version strings are concealed:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Craft CMS instances on {target_ip} are running patched versions (>= 4.18.9 / >= 5.11.2):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Craft CMS instances detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Craft CMS (CVE-2026-115934)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_WEB_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443 8000 3000)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = CraftCmsAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an affected Craft CMS version (CVE-2026-115934).\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} requires manual Craft CMS version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
