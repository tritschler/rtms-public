"""
azul_payara_cve_2026_110003_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and management portal version verification
for Azul Payara Server and Payara Micro deployments against:
  - CVE-2026-110003 (CVSS 9.3 Critical): Administration REST interface authentication bypass
    via X-GlassFish-authToken header on domains with default/empty admin credentials.
  - CVE-2026-90908 (CVSS 9.3 Critical): GenericAdminAuthenticator JMX/RMI administrative access
    restriction bypass via client host address spoofing.

Affected Versions:
  - Azul Payara Server / Micro 7.x Enterprise: 7.0.0 prior to 7.6.0 (Fixed in 7.6.0+)
  - Azul Payara Server / Micro 7.x Community: 7.2024.1 prior to 7.2026.11 (Fixed in 7.2026.11+)
  - Azul Payara Server / Micro 6.x Enterprise: 6.0.0 prior to 6.44.0 (Fixed in 6.44.0+)
  - Azul Payara Server / Micro 6.x Community: 6.2022.1 through 6.2025.11 (Fixed in 6.2026.1+)
  - Azul Payara Server / Micro 5.x Enterprise: 5.20.0 prior to 5.93.0 (Fixed in 5.93.0+)
  - Azul Payara Server / Micro 5.x Community: 5.181 through 5.2022.5 (End of Community Support; upgrade to Enterprise 5.93.0+ or 6.x/7.x)
  - Azul Payara Server / Micro 4.x: prior to 4.1.2.191.61 (Fixed in 4.1.2.191.61+)

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
                return self.format_result("Skipped", details="Requirements not met (no target Azul Payara ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_PAYARA_PORTS = [4848, 8080, 8181, 8443, 80, 443]
SSL_PORTS = {443, 4848, 8181, 8443, 9443}


def parse_payara_version(text: str) -> Optional[Tuple[List[int], str]]:
    """
    Extracts Azul Payara Server / Payara Micro version components from HTTP Server headers,
    management REST responses, or Admin Console HTML metadata.
    Examples:
      - 'Payara Server 6.43.0 #badassfish' -> ([6, 43, 0], '6.43.0')
      - 'Payara Server 7.2026.10 #badassfish' -> ([7, 2026, 10], '7.2026.10')
      - 'Payara Micro 5.92.0' -> ([5, 92, 0], '5.92.0')
    """
    if not text:
        return None

    patterns = [
        r"Payara\s+(?:Server|Micro|Platform)?\s*v?([4567](?:\.[0-9]+){1,4})",
        r'"(?:version|payaraVersion|serverVersion)"\s*:\s*"(?:Payara[^0-9]*)?([4567](?:\.[0-9]+){1,4})"',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            ver_str = match.group(1)
            parts = [int(x) for x in ver_str.split(".")]
            return parts, ver_str

    return None


def is_payara_version_vulnerable(parts: List[int], raw_ver: str = "") -> Tuple[bool, str]:
    """
    Evaluates whether an Azul Payara Server / Payara Micro version is affected by
    CVE-2026-110003 & CVE-2026-90908 (CVSS 9.3).
    """
    if not parts:
        return False, "Invalid version format."

    ver_str = raw_ver or ".".join(str(p) for p in parts)
    padded = parts + [0] * (5 - len(parts))
    major = padded[0]
    second = padded[1]
    third = padded[2]

    if major == 7:
        # Community Edition uses year in second segment (e.g., 7.2024.1 .. 7.2026.10)
        if second >= 2024:
            if (second, third) < (2026, 11):
                return True, (
                    f"Azul Payara {ver_str} (Community 7.x) is prior to 7.2026.11 and is affected by "
                    f"CVE-2026-110003 & CVE-2026-90908 (CVSS 9.3 Admin REST & JMX Auth Bypass)."
                )
            return False, f"Azul Payara {ver_str} is patched (>= 7.2026.11) against CVE-2026-110003 & CVE-2026-90908."
        else:
            if (second, third) < (6, 0):
                return True, (
                    f"Azul Payara {ver_str} (Enterprise 7.x) is prior to 7.6.0 and is affected by "
                    f"CVE-2026-110003 & CVE-2026-90908 (CVSS 9.3 Admin REST & JMX Auth Bypass)."
                )
            return False, f"Azul Payara {ver_str} is patched (>= 7.6.0) against CVE-2026-110003 & CVE-2026-90908."

    if major == 6:
        if second >= 2022:
            if (second, third) <= (2025, 11):
                return True, (
                    f"Azul Payara {ver_str} (Community 6.x) is <= 6.2025.11 and is affected by "
                    f"CVE-2026-110003 & CVE-2026-90908 (CVSS 9.3)."
                )
            return False, f"Azul Payara {ver_str} is patched (> 6.2025.11) against CVE-2026-110003 & CVE-2026-90908."
        else:
            if (second, third) < (44, 0):
                return True, (
                    f"Azul Payara {ver_str} (Enterprise 6.x) is prior to 6.44.0 and is affected by "
                    f"CVE-2026-110003 & CVE-2026-90908 (CVSS 9.3)."
                )
            return False, f"Azul Payara {ver_str} is patched (>= 6.44.0) against CVE-2026-110003 & CVE-2026-90908."

    if major == 5:
        if second >= 181:
            return True, (
                f"Azul Payara {ver_str} (Community 5.x) is affected by CVE-2026-110003 & CVE-2026-90908 "
                f"(upgrade to Payara Enterprise >= 5.93.0, >= 6.44.0, or >= 7.6.0)."
            )
        else:
            if (second, third) < (93, 0):
                return True, (
                    f"Azul Payara {ver_str} (Enterprise 5.x) is prior to 5.93.0 and is affected by "
                    f"CVE-2026-110003 & CVE-2026-90908 (CVSS 9.3)."
                )
            return False, f"Azul Payara {ver_str} is patched (>= 5.93.0) against CVE-2026-110003 & CVE-2026-90908."

    if major == 4:
        if tuple(padded[:5]) < (4, 1, 2, 191, 61):
            return True, (
                f"Azul Payara {ver_str} (4.x) is prior to 4.1.2.191.61 and is affected by "
                f"CVE-2026-110003 & CVE-2026-90908 (CVSS 9.3)."
            )
        return False, f"Azul Payara {ver_str} is patched (>= 4.1.2.191.61) against CVE-2026-110003 & CVE-2026-90908."

    return False, f"Azul Payara {ver_str} is outside the affected 4.x–7.x branches."


class AzulPayaraAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Azul Payara Server & Payara Micro Version Compliance Audit
    (CVE-2026-110003 & CVE-2026-90908).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Azul Payara Server & Micro Admin Auth Bypass Audit (CVE-2026-110003)",
            "description": (
                "Passive version compliance check for Azul Payara Server and Payara Micro against "
                "CVE-2026-110003 (CVSS 9.3 Admin REST Auth Bypass) and CVE-2026-90908 (CVSS 9.3 JMX/RMI Bypass)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-110003",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_PAYARA_PORTS.copy()
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
                    or "payara" in s_name
                    or "glassfish" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 4848, 8080, 8181, 8443):
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
        use_ssl: Optional[bool] = None,
        timeout: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        ssl_flag = (port in SSL_PORTS) if use_ssl is None else use_ssl
        conn = None

        try:
            if ssl_flag:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target_ip, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target_ip, port=port, timeout=timeout)

            headers = {
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-110003)",
                "Accept": "application/json,text/html,*/*",
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
            ("/management/domain/version", "Payara Management REST version endpoint"),
            ("/common/index.jsf", "Payara Admin Console login page"),
            ("/", "Payara HTTP root banner"),
        ]

        payara_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe and port == 4848:
                # Port 4848 may run plain HTTP if secure-admin is not yet enabled
                probe = self.probe_http_endpoint(target_ip, port, path=path, use_ssl=False, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"
            combined_lower = combined.lower()

            if "payara" in combined_lower or "#badassfish" in combined_lower:
                payara_detected = True
                detected_source = source_label

                ver_info = parse_payara_version(combined)
                if ver_info:
                    parts, ver_str = ver_info
                    is_vuln, reason = is_payara_version_vulnerable(parts, ver_str)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if payara_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Azul Payara service is active, but exact version banner is concealed "
                    "(e.g., server header stripped). Verify version >= 7.6.0 / >= 7.2026.11 / >= 6.44.0 / >= 5.93.0."
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
                    f"- [{port_label}] Azul Payara {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Azul Payara {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-110003 / CVE-2026-90908 affected Azul Payara version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-110003 & CVE-2026-90908 - CVSS 9.3):\n"
                f"The target host {target_ip} runs an affected Azul Payara Server or Payara Micro release.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-110003 (CVSS 9.3): Unauthenticated remote access bypass in the administration REST "
                f"interface via the X-GlassFish-authToken HTTP header.\n"
                f"- CVE-2026-90908 (CVSS 9.3): Unauthenticated bypass of JMX/RMI administrative access restrictions "
                f"in GenericAdminAuthenticator.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Azul Payara Enterprise to >= 7.6.0, >= 6.44.0, >= 5.93.0, or >= 4.1.2.191.61 "
                f"(or Payara Community to >= 7.2026.11).\n"
                f"2. Ensure a strong non-empty administrator password is set and restrict port 4848 / JMX ports."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Azul Payara service detected (version banner concealed)."
            details = (
                f"Azul Payara service detected on {target_ip}; manual version verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Azul Payara instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Azul Payara Server or Payara Micro services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Azul Payara Server & Micro (CVE-2026-110003 & CVE-2026-90908)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_PAYARA_PORTS,
        help="Ports to inspect (default: 4848 8080 8181 8443 80 443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = AzulPayaraAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an Azul Payara version affected by CVE-2026-110003 / CVE-2026-90908.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes Azul Payara services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
