"""
apache_tomcat_cve_2026_133325_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and version verification for
Apache Tomcat server instances to check patch compliance against:
  - CVE-2026-133325 (CVSS 9.8): Key exchange without entity authentication in
    clusters secured with TLS 1.3 and TLS-PSK (11.0.28-11.0.29, 10.1.62, 9.0.124).
  - CVE-2026-118028 (CVSS 9.1): Execution After Redirect (EAR) in RedirectValve
    (11.0.0-M18 through 11.0.27, 10.1.20 through 10.1.61, 9.0.87 through 9.0.123).
  - CVE-2026-116561 (CVSS 9.1): Improper cleanup on thrown exception in Jakarta
    Authentication secureResponse() (11.0.0-M1 through 11.0.27, 10.1.0-M1 through
    10.1.61, 9.0.0.M1 through 9.0.123, EOL 8.5.0 through 8.5.100).
  - CVE-2026-95517 (CVSS 9.1): Encryption of security-relevant inputs without
    integrity verification in EncryptInterceptor (11.0.0-M1 through 11.0.27,
    10.1.0-M1 through 10.1.61, 9.0.13 through 9.0.123, EOL 8.5.38-8.5.100, 7.0.100-7.0.109).

Fixed in: Apache Tomcat 11.0.30+, 10.1.63+, and 9.0.125+.

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

DEFAULT_WEB_PORTS = [8080, 8443, 80, 443, 8000, 8888, 9443]
SSL_PORTS = {443, 8443, 9443}


def parse_apache_tomcat_version(text: str) -> Optional[Tuple[int, int, int, str, str]]:
    """
    Extracts Apache Tomcat version (major, minor, patch, qualifier, raw_str) from:
      - HTTP Server headers: 'Apache-Coyote/1.1', 'Apache Tomcat/10.1.62'
      - HTML error / welcome banners: 'Apache Tomcat/11.0.29', 'Apache Tomcat Version 9.0.123'
    """
    if not text:
        return None

    patterns = [
        r"Apache\s+Tomcat(?:\s+Version)?[/\s\-:v]+([0-9]+)\.([0-9]+)\.([0-9]+)(?:[\.\-]([a-zA-Z0-9.\-]+))?",
        r"\bTomcat[/\s\-:v]+([0-9]+)\.([0-9]+)\.([0-9]+)(?:[\.\-]([a-zA-Z0-9.\-]+))?",
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


def is_apache_tomcat_version_vulnerable(
    major: int, minor: int, patch: int, qualifier: str = "", raw_str: str = ""
) -> Tuple[bool, str]:
    """
    Evaluates whether an Apache Tomcat version is affected by:
      - CVE-2026-133325 (11.0.28-11.0.29, 10.1.62, 9.0.124)
      - CVE-2026-118028 (11.0.0-M18..11.0.27, 10.1.20..10.1.61, 9.0.87..9.0.123)
      - CVE-2026-116561 (11.0.0-M1..11.0.27, 10.1.0-M1..10.1.61, 9.0.0.M1..9.0.123, 8.5.0..8.5.100)
      - CVE-2026-95517  (11.0.0-M1..11.0.27, 10.1.0-M1..10.1.61, 9.0.13..9.0.123, 8.5.38..8.5.100, 7.0.100..7.0.109)
    Patched versions: >= 11.0.30 (11.x), >= 10.1.63 (10.1.x), >= 9.0.125 (9.0.x).
    """
    ver_str = raw_str or (f"{major}.{minor}.{patch}-{qualifier}" if qualifier else f"{major}.{minor}.{patch}")

    if major <= 8:
        return True, (
            f"Apache Tomcat {ver_str} (EOL branch) is affected by CVE-2026-116561 and CVE-2026-95517 "
            f"(requires migration to a supported patched release: >= 9.0.125, >= 10.1.63, or >= 11.0.30)."
        )

    if major == 9 and minor == 0:
        if patch < 124:
            return True, (
                f"Apache Tomcat {ver_str} is affected by CVE-2026-118028, CVE-2026-116561, and CVE-2026-95517 "
                f"(affected: 9.0.x < 9.0.125; requires upgrade to >= 9.0.125)."
            )
        if patch == 124:
            return True, (
                f"Apache Tomcat {ver_str} is affected by CVE-2026-133325 "
                f"(affected: 9.0.124; requires upgrade to >= 9.0.125)."
            )
        return False, (
            f"Apache Tomcat {ver_str} is patched against CVE-2026-133325, CVE-2026-118028, "
            f"CVE-2026-116561, and CVE-2026-95517 (running >= 9.0.125)."
        )

    if major == 10:
        if minor == 0 or (minor == 1 and patch < 62):
            return True, (
                f"Apache Tomcat {ver_str} is affected by CVE-2026-118028, CVE-2026-116561, and CVE-2026-95517 "
                f"(affected: 10.1.x < 10.1.63; requires upgrade to >= 10.1.63)."
            )
        if minor == 1 and patch == 62:
            return True, (
                f"Apache Tomcat {ver_str} is affected by CVE-2026-133325 "
                f"(affected: 10.1.62; requires upgrade to >= 10.1.63)."
            )
        return False, (
            f"Apache Tomcat {ver_str} is patched against CVE-2026-133325, CVE-2026-118028, "
            f"CVE-2026-116561, and CVE-2026-95517 (running >= 10.1.63)."
        )

    if major == 11 and minor == 0:
        if patch < 28:
            return True, (
                f"Apache Tomcat {ver_str} is affected by CVE-2026-118028, CVE-2026-116561, and CVE-2026-95517 "
                f"(affected: 11.0.x < 11.0.30; requires upgrade to >= 11.0.30)."
            )
        if patch in (28, 29):
            return True, (
                f"Apache Tomcat {ver_str} is affected by CVE-2026-133325 "
                f"(affected: 11.0.28-11.0.29; requires upgrade to >= 11.0.30)."
            )
        return False, (
            f"Apache Tomcat {ver_str} is patched against CVE-2026-133325, CVE-2026-118028, "
            f"CVE-2026-116561, and CVE-2026-95517 (running >= 11.0.30)."
        )

    return False, (
        f"Apache Tomcat {ver_str} is not in an affected version range for CVE-2026-133325, "
        f"CVE-2026-118028, CVE-2026-116561, or CVE-2026-95517."
    )


class ApacheTomcatAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Apache Tomcat Multi-CVE Version Compliance Audit (CVE-2026-133325).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Apache Tomcat Multi-CVE Version Compliance Audit (CVE-2026-133325)",
            "description": (
                "Passive version compliance check for Apache Tomcat < 11.0.30, < 10.1.63, and < 9.0.125 "
                "(CVE-2026-133325, CVE-2026-118028, CVE-2026-116561, CVE-2026-95517 — CVSS 9.8)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-133325 / CVE-2026-118028 / CVE-2026-116561 / CVE-2026-95517",
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
                    or "tomcat" in s_name
                    or "coyote" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (8080, 8443, 80, 443, 8000, 8888, 9443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-133325)",
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
            ("/docs/", "Apache Tomcat Documentation Page"),
            ("/RELEASE-NOTES.txt", "Apache Tomcat Release Notes"),
        ]

        tomcat_detected = False
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

            if "apache tomcat" in combined_lower or "tomcat/" in combined_lower or "apache-coyote" in combined_lower:
                tomcat_detected = True
                detected_source = f"{source_label} ({path})"

                ver_info = parse_apache_tomcat_version(combined)
                if ver_info:
                    major, minor, patch, qualifier, ver_str = ver_info
                    is_vuln, reason = is_apache_tomcat_version_vulnerable(major, minor, patch, qualifier, ver_str)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if tomcat_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Apache Tomcat is active on this endpoint, but its exact version string is concealed. "
                    "Verify that Apache Tomcat is updated to >= 11.0.30, >= 10.1.63, or >= 9.0.125."
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
                    f"- [{port_label}] Apache Tomcat {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Apache Tomcat {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated Apache Tomcat version detected on {target_ip} "
                f"(CVE-2026-133325 / CVE-2026-118028 / CVE-2026-116561 / CVE-2026-95517).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (Apache Tomcat < 11.0.30 / < 10.1.63 / < 9.0.125 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an unpatched version of Apache Tomcat.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-133325 (CVSS 9.8): Key exchange without entity authentication in TLS 1.3 + TLS-PSK clusters.\n"
                f"- CVE-2026-118028 (CVSS 9.1): Execution After Redirect (EAR) in RedirectValve.\n"
                f"- CVE-2026-116561 (CVSS 9.1): Improper exception cleanup in Jakarta Authentication secureResponse().\n"
                f"- CVE-2026-95517 (CVSS 9.1): Missing integrity verification in EncryptInterceptor.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Apache Tomcat to version 11.0.30+, 10.1.63+, or 9.0.125+.\n"
                f"2. If using cluster TLS-PSK prior to upgrading, use TLS 1.2 with TLS-PSK as recommended by the vendor."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Apache Tomcat active with concealed version metadata."
            details = (
                f"Apache Tomcat detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Info", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Apache Tomcat instances on {target_ip} are running versions compliant against "
                f"CVE-2026-133325, CVE-2026-118028, CVE-2026-116561, and CVE-2026-95517:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Apache Tomcat installations detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance audit for Apache Tomcat (CVE-2026-133325)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[8080, 8443, 80, 443])
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    plugin = ApacheTomcatAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        sys.exit(0)
    res = plugin.run_audit(args.target, args.ports)
    if res.get("status") == "Vulnerable":
        print(res.get("details", ""))
        sys.exit(1)
    print(res.get("details", ""))
    sys.exit(0)
