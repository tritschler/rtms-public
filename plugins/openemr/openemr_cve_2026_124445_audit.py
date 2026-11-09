"""
openemr_cve_2026_124445_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for OpenEMR installations
to check patch compliance against:
  - CVE-2026-124445 (CVSS 9.3, affected: >= 7.0.1 and < 8.4.0)
  - CVE-2026-124490 (CVSS 9.4, affected: < 8.3.0)
  - CVE-2026-124469 (CVSS 9.4, affected: < 8.3.0)
  - CVE-2026-124463 (CVSS 9.3, affected: < 8.3.0)
  - CVE-2026-124450 (CVSS 9.3, affected: < 8.3.0)

Fixed in: OpenEMR 8.4.0+ (8.3.0+ for CVE-2026-124490/124469/124463/124450).

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

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8300, 9300]
SSL_PORTS = {443, 8443, 9300, 9443}


def parse_openemr_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts OpenEMR semantic version (major, minor, patch, raw_str) from:
      - OpenEMR admin.php or login page version strings: 'v8.2.0', 'OpenEMR 8.2.0', '7.0.2 (1)'
      - Version headers or asset parameters: 'Version: 8.2.0'
    """
    if not text:
        return None

    patterns = [
        r"OpenEMR\s+v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\s*\([0-9]+\))?",
        r"<td>\s*v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:\s*\([0-9]+\))?\s*</td>",
        r"(?:Version|version_number)\s*[:=]\s*[\"']?v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)$",
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


def is_openemr_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether an OpenEMR version tuple (major, minor, patch) is affected by:
      - CVE-2026-124490, CVE-2026-124469, CVE-2026-124463, CVE-2026-124450 (< 8.3.0)
      - CVE-2026-124445 (>= 7.0.1 and < 8.4.0)
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    applicable_cves: List[str] = []
    if ver_tuple < (8, 3, 0):
        applicable_cves.extend([
            "CVE-2026-124490",
            "CVE-2026-124469",
            "CVE-2026-124463",
            "CVE-2026-124450",
        ])
    if (7, 0, 1) <= ver_tuple < (8, 4, 0):
        applicable_cves.append("CVE-2026-124445")

    if applicable_cves:
        cve_list_str = ", ".join(applicable_cves)
        return True, (
            f"OpenEMR {ver_str} is affected by {cve_list_str} "
            f"(requires upgrade to OpenEMR >= 8.4.0)."
        )

    return False, (
        f"OpenEMR {ver_str} is patched against CVE-2026-124445, CVE-2026-124490, "
        f"CVE-2026-124469, CVE-2026-124463, and CVE-2026-124450 (running >= 8.4.0)."
    )


class OpenEMRAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: OpenEMR Version Compliance Audit
    (CVE-2026-124445, CVE-2026-124490, CVE-2026-124469, CVE-2026-124463, CVE-2026-124450).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "OpenEMR Multi-CVE Version Compliance Audit (CVE-2026-124445 / CVE-2026-124490)",
            "description": (
                "Passive version compliance check for OpenEMR < 8.4.0 "
                "(CVE-2026-124445, CVE-2026-124490, CVE-2026-124469, CVE-2026-124463, CVE-2026-124450)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-124445, CVE-2026-124490, CVE-2026-124469, CVE-2026-124463, CVE-2026-124450",
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
                    or "openemr" in s_name
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
        use_ssl = port in SSL_PORTS or port in (443, 8443, 9300, 9443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-124445)",
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
        candidate_paths = [
            ("/interface/login/login.php", "OpenEMR Login Page"),
            ("/openemr/interface/login/login.php", "OpenEMR Login Page (/openemr)"),
            ("/admin.php", "OpenEMR Site Administration Page"),
            ("/openemr/admin.php", "OpenEMR Site Administration Page (/openemr)"),
        ]

        openemr_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe or probe.get("status_code") not in (200, 302):
                continue

            body = probe.get("body_snippet", "")
            headers = probe.get("headers", {})
            body_lower = body.lower()

            if (
                "openemr" in body_lower
                or "openemr" in headers.get("set-cookie", "").lower()
                or "openemr" in headers.get("location", "").lower()
            ):
                openemr_detected = True
                detected_source = f"{source_label} ({path})"

                ver_info = parse_openemr_version(body)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_openemr_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if openemr_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "OpenEMR web interface is active on this endpoint, but its exact version string "
                    "is concealed. Verify that OpenEMR is updated to >= 8.4.0."
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
                    f"- [{port_label}] OpenEMR {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] OpenEMR {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated OpenEMR version detected on {target_ip} "
                f"(CVE-2026-124445 / CVE-2026-124490 / CVE-2026-124469 / CVE-2026-124463 / CVE-2026-124450).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (OpenEMR < 8.4.0 - CVSS up to 9.4):\n"
                f"The target host {target_ip} runs an unpatched version of OpenEMR.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade OpenEMR to version 8.4.0 or later.\n"
                f"2. Restrict public access to /admin.php and administrative modules."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "OpenEMR active with concealed version metadata."
            details = (
                f"OpenEMR detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings) + "\n\n"
                f"Please verify in OpenEMR About page that the installation is updated to version 8.4.0+."
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: OpenEMR instances on {target_ip} are running patched versions (>= 8.4.0):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected OpenEMR installations detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance audit for OpenEMR (CVE-2026-124445 / CVE-2026-124490)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 8080, 8443, 8300, 9300],
        help="Ports to inspect (default: 80 443 8080 8443 8300 9300)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)",
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - OpenEMR Version Compliance Auditor")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = OpenEMRAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} runs an unpatched OpenEMR version!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual patch verification.\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(0)
    elif status == "OK":
        print(f"✅ [SAFE] {args.target} passed audit.")
        print(f"   {result.get('details', '')}\n")
        sys.exit(0)
    else:
        print(f"ℹ️  [{status}] {result.get('details', '')}\n")
        sys.exit(0)
