"""
sogo_cve_2026_127131_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for Alinto SOGo
Groupware / Webmail deployments (including Mailcow & iRedMail stacks) against:
  - CVE-2026-127131 (CVSS 9.1 Critical): Missing rate limiting in SOGo web login
    TOTP 2FA verification (/SOGo/connect) enabling high-speed 2FA brute-force without lockout.
  - CVE-2026-127111 (CVSS 9.1 Critical): Unrestricted authentication attempts in
    SOGo passwordRecoveryCheck endpoint enabling unauthenticated account takeover.

Affected Versions:
  - Alinto SOGo prior to 5.12.13 (Fixed in 5.12.13+)

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
                return self.format_result("Skipped", details="Requirements not met (no target SOGo HTTP/HTTPS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_SOGO_PORTS = [80, 443, 20000, 8080, 8443]
SSL_PORTS = {443, 8443, 9443}


def parse_sogo_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts SOGo version tuple (major, minor, patch, raw_version_str)
    from /SOGo/ HTML assets, woa/WebServerResources, or HTTP headers.
    """
    if not text:
        return None

    patterns = [
        r"SOGo(?:\s+v?|[/-])([2-5])\.([0-9]{1,2})\.([0-9]{1,2})",
        r"WebServerResources(?:\?v=|/)([2-5])\.([0-9]{1,2})\.([0-9]{1,2})",
        r'sogoVersion\s*[:=]\s*["\']v?([2-5])\.([0-9]{1,2})\.([0-9]{1,2})',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            ver_str = f"{major}.{minor}.{patch}"
            return major, minor, patch, ver_str

    return None


def is_sogo_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether an Alinto SOGo version is affected by CVE-2026-127131 & CVE-2026-127111 (CVSS 9.1).
      - < 5.12.13 -> Vulnerable
    """
    ver_str = f"{major}.{minor}.{patch}"

    if (major, minor, patch) < (5, 12, 13):
        return True, (
            f"SOGo {ver_str} is prior to 5.12.13 and is affected by CVE-2026-127131 (TOTP 2FA Brute-Force) "
            f"and CVE-2026-127111 (Unauthenticated Password Recovery Takeover)."
        )

    return False, f"SOGo {ver_str} is patched (>= 5.12.13) against CVE-2026-127131 and CVE-2026-127111."


class SogoGroupwareAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Alinto SOGo Groupware Version Compliance Audit
    (CVE-2026-127131 & CVE-2026-127111 - CVSS 9.1).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "SOGo Groupware 2FA & Account Recovery Bypass Audit (CVE-2026-127131)",
            "description": (
                "Passive version compliance check for Alinto SOGo Groupware / Webmail (< 5.12.13) "
                "against CVE-2026-127131 (CVSS 9.1 TOTP 2FA Bypass) and CVE-2026-127111 (CVSS 9.1 Password Recovery Bypass)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-127131",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_SOGO_PORTS.copy()
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
                    or "sogo" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 20000, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/SOGo/",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-127131)",
                "Accept": "text/html,application/json,*/*",
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
            ("/SOGo/", "SOGo Webmail /SOGo/ portal"),
            ("/SOGo.woa/WebServerResources/", "SOGo WebServerResources static metadata"),
        ]

        sogo_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"
            combined_lower = combined.lower()

            if (
                "sogo" in combined_lower
                or "sogo.woa" in combined_lower
                or "x-worequest-id" in combined_lower
            ):
                sogo_detected = True
                detected_source = source_label

                ver_info = parse_sogo_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_sogo_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if sogo_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "SOGo Groupware portal is active, but exact version string is concealed. "
                    "Verify SOGo version >= 5.12.13 for CVE-2026-127131 & CVE-2026-127111 compliance."
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
                    f"- [{port_label}] SOGo {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] SOGo {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-127131 / CVE-2026-127111 affected SOGo Groupware version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-127131 & CVE-2026-127111 - CVSS 9.1):\n"
                f"The target host {target_ip} runs an affected Alinto SOGo Groupware release (< 5.12.13).\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-127131 (CVSS 9.1): Missing rate limiting in SOGo TOTP 2FA verification (/SOGo/connect).\n"
                f"- CVE-2026-127111 (CVSS 9.1): Unrestricted secret-question brute-force in passwordRecoveryCheck.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade SOGo Groupware to version 5.12.13 or later.\n"
                f"2. Enforce reverse-proxy rate limiting on /SOGo/connect and /SOGo/so/passwordRecoveryCheck."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "SOGo Groupware service detected (version concealed)."
            details = (
                f"SOGo service detected on {target_ip}; manual version verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: SOGo instance on {target_ip} meets the minimum patched release (>= 5.12.13):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Alinto SOGo Groupware services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Alinto SOGo Groupware (CVE-2026-127131 & CVE-2026-127111)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_SOGO_PORTS,
        help="Ports to inspect (default: 80 443 20000 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = SogoGroupwareAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a SOGo version affected by CVE-2026-127131.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes SOGo services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
