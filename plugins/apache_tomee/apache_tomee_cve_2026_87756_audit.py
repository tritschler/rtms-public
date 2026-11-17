"""
apache_tomee_cve_2026_87756_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and version verification for
Apache TomEE and OpenEJB server instances to check patch compliance against:
  - CVE-2026-87756 (CVSS 9.8): Missing administrative role check on internal
    system EJBs used for remote deployment and configuration.
  - CVE-2026-97880 (CVSS 9.8): Embedded OpenEJB HTTP server dispatches requests
    to HTTP Basic protected REST endpoints without verifying credentials.
  - CVE-2026-97888 (CVSS 9.8): Embedded HTTP server does not clear security
    identity on worker threads between requests.
  - CVE-2026-111240 (CVSS 9.8): JDBC JAAS login module accepts passwordless
    authentication when stored password is NULL.
  - CVE-2026-111244 (CVSS 9.8): Incomplete enforcement of MicroProfile JWT
    role-based access control on JAX-RS resources.
  - CVE-2026-111245 (CVSS 9.8): WS-Security UsernameToken caller identity
    persists on standalone OpenEJB HTTP worker threads across requests.
  - CVE-2026-111250 (CVSS 9.8): Embedded OpenEJB HTTP server reports every
    request as authenticated for programmatic authentication checks.
  - CVE-2026-111256 (CVSS 9.8): Embedded OpenEJB HTTP server ignores configured
    authentication methods on JAX-WS and JAX-RS endpoints.
  - CVE-2026-111264 (CVSS 9.8): Generated security constraints for EJB JAX-WS
    endpoints protect only a subset of HTTP methods.

Fixed in: Apache TomEE 10.3.0+ and 11.0.0-M2+ (11.0.0+).

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

DEFAULT_WEB_PORTS = [8080, 8443, 4204, 80, 443, 9443]
SSL_PORTS = {443, 8443, 9443}


def parse_apache_tomee_version(text: str) -> Optional[Tuple[int, int, int, str, str]]:
    """
    Extracts Apache TomEE / OpenEJB version (major, minor, patch, qualifier, raw_str) from:
      - HTTP Server headers: 'Apache TomEE/10.2.0', 'OpenEJB/4.7.5'
      - HTML error / welcome banners: 'Apache TomEE 11.0.0-M1', 'Apache OpenEJB 10.1.0'
    """
    if not text:
        return None

    patterns = [
        r"(?:Apache[\s\-]+)?TomEE[/\s\-:v]+([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([a-zA-Z0-9.\-]+))?",
        r"(?:Apache[\s\-]+)?OpenEJB[/\s\-:v]+([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([a-zA-Z0-9.\-]+))?",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            qualifier = (match.group(4) or "").strip()
            raw_str = f"{major}.{minor}.{patch}-{qualifier}" if qualifier else f"{major}.{minor}.{patch}"
            return major, minor, patch, qualifier, raw_str

    return None


def is_apache_tomee_version_vulnerable(
    major: int, minor: int, patch: int, qualifier: str = "", raw_str: str = ""
) -> Tuple[bool, str]:
    """
    Evaluates whether an Apache TomEE / OpenEJB version is affected by:
      - CVE-2026-87756, CVE-2026-97880, CVE-2026-97888, CVE-2026-111240,
        CVE-2026-111244, CVE-2026-111245, CVE-2026-111250, CVE-2026-111256,
        CVE-2026-111264.
      Affected: < 10.3.0 (1.x, 4.x, 7.x-9.x, 10.0.0-M1 through 10.2.x) and 11.0.0-M1 (< 11.0.0-M2).
    """
    ver_str = raw_str or (f"{major}.{minor}.{patch}-{qualifier}" if qualifier else f"{major}.{minor}.{patch}")
    ver_tuple = (major, minor, patch)

    if ver_tuple < (10, 3, 0):
        return True, (
            f"Apache TomEE / OpenEJB {ver_str} is affected by CVE-2026-87756, CVE-2026-97880, "
            f"CVE-2026-97888, CVE-2026-111240, CVE-2026-111244, CVE-2026-111245, CVE-2026-111250, "
            f"CVE-2026-111256, and CVE-2026-111264 (affected: < 10.3.0; requires upgrade to >= 10.3.0)."
        )

    if ver_tuple == (11, 0, 0) and qualifier.upper() == "M1":
        return True, (
            f"Apache TomEE / OpenEJB {ver_str} is affected by CVE-2026-87756, CVE-2026-97880, "
            f"CVE-2026-97888, CVE-2026-111240, CVE-2026-111244, CVE-2026-111245, CVE-2026-111250, "
            f"CVE-2026-111256, and CVE-2026-111264 (affected: < 11.0.0-M2; requires upgrade to >= 11.0.0-M2)."
        )

    return False, (
        f"Apache TomEE / OpenEJB {ver_str} is patched against CVE-2026-87756 and related OpenEJB advisories "
        f"(running >= 10.3.0 / >= 11.0.0-M2)."
    )


class ApacheTomEEAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Apache TomEE & OpenEJB Version Compliance Audit (CVE-2026-87756).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Apache TomEE & OpenEJB Version Compliance Audit (CVE-2026-87756)",
            "description": (
                "Passive version compliance check for Apache TomEE & OpenEJB < 10.3.0 and 11.0.0-M1 "
                "(CVE-2026-87756, CVE-2026-97880, CVE-2026-97888, CVE-2026-111240, CVE-2026-111244, "
                "CVE-2026-111245, CVE-2026-111250, CVE-2026-111256, CVE-2026-111264 — CVSS 9.8)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-87756",
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
                    or "tomee" in s_name
                    or "openejb" in s_name
                    or "tomcat" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (8080, 8443, 4204, 80, 443, 9443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-87756)",
                "Accept": "text/html,application/json,text/plain,*/*",
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
            ("/", "HTTP Root Banner"),
            ("/tomee/", "Apache TomEE Console"),
        ]

        tomee_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            combined = f"{server_hdr}\n{headers}\n{body}"
            combined_lower = combined.lower()

            if "tomee" in combined_lower or "openejb" in combined_lower:
                tomee_detected = True
                detected_source = f"{source_label} ({path})"

                ver_info = parse_apache_tomee_version(combined)
                if ver_info:
                    major, minor, patch, qualifier, ver_str = ver_info
                    is_vuln, reason = is_apache_tomee_version_vulnerable(major, minor, patch, qualifier, ver_str)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if tomee_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Apache TomEE / OpenEJB is active on this endpoint, but its exact version string is concealed. "
                    "Verify that Apache TomEE is updated to >= 10.3.0 or >= 11.0.0-M2."
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
                    f"- [{port_label}] Apache TomEE / OpenEJB {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Apache TomEE / OpenEJB {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated Apache TomEE / OpenEJB version detected on {target_ip} "
                f"(CVE-2026-87756 / CVE-2026-97880 / CVE-2026-97888 / CVE-2026-111240 / CVE-2026-111244 / "
                f"CVE-2026-111245 / CVE-2026-111250 / CVE-2026-111256 / CVE-2026-111264).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (Apache TomEE / OpenEJB < 10.3.0 / 11.0.0-M1 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an unpatched version of Apache TomEE / OpenEJB.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-87756, CVE-2026-97880, CVE-2026-97888, CVE-2026-111240, CVE-2026-111244, "
                f"CVE-2026-111245, CVE-2026-111250, CVE-2026-111256, CVE-2026-111264 (CVSS 9.8): "
                f"Multiple authentication bypass, worker thread identity reuse, and remote EJB role verification "
                f"flaws in Apache TomEE and OpenEJB.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Apache TomEE to version 10.3.0+ or 11.0.0-M2+.\n"
                f"2. Restrict network access to the embedded OpenEJB HTTP server and remote EJB endpoints."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Apache TomEE / OpenEJB active with concealed version metadata."
            details = (
                f"Apache TomEE / OpenEJB detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Apache TomEE / OpenEJB instances on {target_ip} are running patched versions "
                f"(>= 10.3.0 / >= 11.0.0-M2):\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Apache TomEE / OpenEJB services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Apache TomEE & OpenEJB (CVE-2026-87756)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_WEB_PORTS,
        help="Ports to inspect (default: 8080 8443 4204 80 443 9443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = ApacheTomEEAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an Apache TomEE / OpenEJB version affected by CVE-2026-87756.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes Apache TomEE / OpenEJB services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
