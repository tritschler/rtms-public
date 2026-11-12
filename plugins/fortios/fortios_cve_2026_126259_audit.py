"""
fortios_cve_2026_126259_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and administrative / SSL-VPN web portal
metadata verification for Fortinet FortiOS (FortiGate) appliances to check patch compliance against:
  - CVE-2026-126259 (CVSS 9.8 Critical): Missing authentication for critical function in
    FortiOS HA FGSP / autoscale configuration synchronization.
  - CVE-2026-126254 (CVSS 9.6 Critical): Numeric truncation error in FortiOS iBGP attribute handling.
  - CVE-2026-126253 (CVSS 9.3 Critical): Authentication bypass in FortiOS OSPF LSA handling.

Affected Versions:
  - FortiOS 8.0.0 through 8.0.1 (Fixed in 8.0.2+)
  - FortiOS 7.6.0 through 7.6.7 (Fixed in 7.6.8+)
  - FortiOS 7.4.0 through 7.4.12 (Fixed in 7.4.13+)
  - FortiOS 7.2.0 through 7.2.13 (Fixed in 7.2.14+)
  - FortiOS 7.0.0 through 7.0.19 (Fixed in 7.0.20+)

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
                return self.format_result("Skipped", details="Requirements not met (no target FortiOS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_FORTIOS_PORTS = [443, 8443, 10443, 80]
SSL_PORTS = {443, 8443, 9443, 10443}


def parse_fortios_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts FortiOS version tuple (major, minor, patch, raw_version_str)
    from HTTP headers, administrative portal metadata, or static asset paths.
    Examples:
      - 'FortiOS v7.6.6-build3510' -> (7, 6, 6, '7.6.6')
      - 'FortiGate-VM64 v7.4.11' -> (7, 4, 11, '7.4.11')
      - 'fgt_version = "8.0.0"' -> (8, 0, 0, '8.0.0')
    """
    if not text:
        return None

    patterns = [
        r"(?:FortiOS|FortiGate)(?:-[A-Za-z0-9_]+)?\s+v?([78])\.([0-9]+)\.([0-9]+)",
        r"(?:fgt_version|FOS_VERSION|fortios_version|version_str)\s*[:=]\s*[\"']?v?([78])\.([0-9]+)\.([0-9]+)",
        r"/ng/[a-z0-9_-]*v([78])\.([0-9]+)\.([0-9]+)",
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


def is_fortios_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a FortiOS version (major, minor, patch) is affected by
    CVE-2026-126259 (CVSS 9.8), CVE-2026-126254 (CVSS 9.6), and CVE-2026-126253 (CVSS 9.3).
      - 7.0.0 through 7.0.19 -> Vulnerable (Fixed in 7.0.20+)
      - 7.2.0 through 7.2.13 -> Vulnerable (Fixed in 7.2.14+)
      - 7.4.0 through 7.4.12 -> Vulnerable (Fixed in 7.4.13+)
      - 7.6.0 through 7.6.7  -> Vulnerable (Fixed in 7.6.8+)
      - 8.0.0 through 8.0.1  -> Vulnerable (Fixed in 8.0.2+)
    """
    ver_str = f"{major}.{minor}.{patch}"

    if (major, minor) == (7, 0):
        if 0 <= patch <= 19:
            return True, (
                f"FortiOS {ver_str} is in the affected range 7.0.0–7.0.19 for CVE-2026-126259 "
                f"(upgrade to >= 7.0.20)."
            )
        return False, f"FortiOS {ver_str} is patched (>= 7.0.20) against CVE-2026-126259."

    if (major, minor) == (7, 2):
        if 0 <= patch <= 13:
            return True, (
                f"FortiOS {ver_str} is in the affected range 7.2.0–7.2.13 for CVE-2026-126259, "
                f"CVE-2026-126254, and CVE-2026-126253 (upgrade to >= 7.2.14)."
            )
        return False, f"FortiOS {ver_str} is patched (>= 7.2.14) against CVE-2026-126259 / CVE-2026-126254 / CVE-2026-126253."

    if (major, minor) == (7, 4):
        if 0 <= patch <= 12:
            return True, (
                f"FortiOS {ver_str} is in the affected range 7.4.0–7.4.12 for CVE-2026-126259, "
                f"CVE-2026-126254, and CVE-2026-126253 (upgrade to >= 7.4.13)."
            )
        return False, f"FortiOS {ver_str} is patched (>= 7.4.13) against CVE-2026-126259 / CVE-2026-126254 / CVE-2026-126253."

    if (major, minor) == (7, 6):
        if 0 <= patch <= 7:
            return True, (
                f"FortiOS {ver_str} is in the affected range 7.6.0–7.6.7 for CVE-2026-126259, "
                f"CVE-2026-126254, and CVE-2026-126253 (upgrade to >= 7.6.8)."
            )
        return False, f"FortiOS {ver_str} is patched (>= 7.6.8) against CVE-2026-126259 / CVE-2026-126254 / CVE-2026-126253."

    if (major, minor) == (8, 0):
        if patch == 0:
            return True, (
                f"FortiOS {ver_str} is affected by CVE-2026-126259, CVE-2026-126254, "
                f"and CVE-2026-126253 (upgrade to >= 8.0.2)."
            )
        if patch == 1:
            return True, (
                f"FortiOS {ver_str} is affected by CVE-2026-126254 and CVE-2026-126253 "
                f"(upgrade to >= 8.0.2)."
            )
        return False, f"FortiOS {ver_str} is patched (>= 8.0.2) against CVE-2026-126259 / CVE-2026-126254 / CVE-2026-126253."

    return False, f"FortiOS {ver_str} is outside the affected branches (7.0, 7.2, 7.4, 7.6, 8.0)."


class FortiOSAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Fortinet FortiOS Version Compliance Audit
    (CVE-2026-126259, CVE-2026-126254, CVE-2026-126253).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Fortinet FortiOS Version Compliance Audit (CVE-2026-126259)",
            "description": (
                "Passive version compliance check for Fortinet FortiOS (FortiGate) appliances "
                "against CVE-2026-126259 (CVSS 9.8), CVE-2026-126254 (CVSS 9.6), and CVE-2026-126253 (CVSS 9.3)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-126259",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_FORTIOS_PORTS.copy()
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
                    or "forti" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 8080, 8443, 10443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/login",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-126259)",
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
            ("/login", "FortiOS administrative /login portal"),
            ("/remote/login", "FortiOS SSL-VPN /remote/login portal"),
            ("/ng", "FortiOS /ng web management interface"),
        ]

        fortios_detected = False
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
                "fortios" in combined_lower
                or "fortigate" in combined_lower
                or "fgt_lang" in combined_lower
                or "fgt_version" in combined_lower
                or "top.location=\"/ng\"" in combined_lower
            ):
                fortios_detected = True
                detected_source = source_label

                ver_info = parse_fortios_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_fortios_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if fortios_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "FortiOS management or SSL-VPN interface is active, but the exact firmware version "
                    "is concealed in unauthenticated responses. Verify firmware >= 7.0.20 / 7.2.14 / 7.4.13 / 7.6.8 / 8.0.2."
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
                    f"- [{port_label}] FortiOS {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] FortiOS {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-126259 / CVE-2026-126254 / CVE-2026-126253 affected Fortinet FortiOS version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-126259 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an affected Fortinet FortiOS firmware release.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-126259 (CVSS 9.8): Missing authentication for critical function in FortiOS HA FGSP / autoscale.\n"
                f"- CVE-2026-126254 (CVSS 9.6): Numeric truncation error in FortiOS iBGP attribute processing.\n"
                f"- CVE-2026-126253 (CVSS 9.3): Authentication bypass in FortiOS OSPF LSA handling.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade FortiOS to version 7.0.20+, 7.2.14+, 7.4.13+, 7.6.8+, or 8.0.2+.\n"
                f"2. Restrict HA, BGP, OSPF, and administrative interfaces via strict local-in policies and trusted hosts."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "FortiOS service detected (firmware version concealed)."
            details = (
                f"FortiOS service detected on {target_ip}; manual firmware verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: FortiOS instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Fortinet FortiOS services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Fortinet FortiOS (CVE-2026-126259)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_FORTIOS_PORTS,
        help="Ports to inspect (default: 443 8443 10443 80)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = FortiOSAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a FortiOS version affected by CVE-2026-126259.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes FortiOS services requiring firmware verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
