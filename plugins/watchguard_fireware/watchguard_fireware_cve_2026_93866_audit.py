"""
watchguard_fireware_cve_2026_93866_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS portal and banner verification for
WatchGuard Fireware OS (Access Portal / AuthPoint Gateway) and SonicWall SMA1000
appliances to check patch compliance against:
  - CVE-2026-93866 (CVSS 9.2 Critical): Unauthenticated heap buffer overflow via integer
    overflow in WatchGuard Fireware OS Access Portal WebSocket handling.
  - CVE-2026-103594 (CVSS 9.5 Critical): Stack-based buffer overflow in WatchGuard
    Fireware OS WireGuard configuration processing.
  - CVE-2026-121639 (CVSS 9.2 Critical): Missing authentication for critical function
    in WatchGuard AuthPoint Gateway.
  - CVE-2026-83548 (CVSS 10.0 Critical): Pre-authentication SSRF in SonicWall SMA1000
    (SMA6210, SMA7210, SMA8200v) WorkPlace interface.

Affected Versions:
  - WatchGuard Fireware OS 12.x prior to 12.11.4 (Fixed in 12.11.4+)
  - SonicWall SMA1000 12.4.x prior to 12.4.3-03095 (Fixed in 12.4.3-03095+)

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
                return self.format_result("Skipped", details="Requirements not met (no target WatchGuard/SonicWall VPN ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_VPN_APPLIANCE_PORTS = [443, 4100, 8080, 8443]
SSL_PORTS = {443, 4100, 8443}


def parse_fireware_or_sma_version(text: str) -> Optional[Tuple[str, int, int, int, str]]:
    """
    Extracts vendor ('watchguard' or 'sonicwall_sma') and version tuple (major, minor, patch, raw_str).
    """
    if not text:
        return None

    wg_pat = r"(?:Fireware(?:\s+OS|(?:\s+XTM))?|wg_version|fireware_version)\s*[:=v\s]*[\"']?([1][12])\.([0-9]{1,2})\.([0-9]{1,2})"
    m_wg = re.search(wg_pat, text, re.IGNORECASE)
    if m_wg:
        maj, minr, pat = int(m_wg.group(1)), int(m_wg.group(2)), int(m_wg.group(3))
        return "watchguard", maj, minr, pat, f"{maj}.{minr}.{pat}"

    sma_pat = r"(?:SMA\s*1000|WorkPlace|sma_version)\s*[:=v\s]*[\"']?([1][2])\.([0-9]{1,2})\.([0-9]{1,2})"
    m_sma = re.search(sma_pat, text, re.IGNORECASE)
    if m_sma:
        maj, minr, pat = int(m_sma.group(1)), int(m_sma.group(2)), int(m_sma.group(3))
        return "sonicwall_sma", maj, minr, pat, f"{maj}.{minr}.{pat}"

    return None


def is_vpn_appliance_vulnerable(vendor: str, major: int, minor: int, patch: int) -> Tuple[bool, str]:
    ver_str = f"{major}.{minor}.{patch}"
    if vendor == "watchguard":
        if (major, minor, patch) < (12, 11, 4):
            return True, (
                f"WatchGuard Fireware OS {ver_str} is prior to 12.11.4 and is affected by "
                f"CVE-2026-93866 (CVSS 9.2) and CVE-2026-103594 (CVSS 9.5)."
            )
        return False, f"WatchGuard Fireware OS {ver_str} is patched (>= 12.11.4) against CVE-2026-93866 / CVE-2026-103594."

    if vendor == "sonicwall_sma":
        if (major, minor, patch) < (12, 4, 3):
            return True, (
                f"SonicWall SMA1000 {ver_str} is prior to 12.4.3-03095 and is affected by "
                f"CVE-2026-83548 (CVSS 10.0 Pre-Auth SSRF)."
            )
        return False, f"SonicWall SMA1000 {ver_str} is patched (>= 12.4.3) against CVE-2026-83548."

    return False, f"Version {ver_str} is outside affected ranges."


class WatchGuardSonicWallVpnAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: WatchGuard Fireware OS & SonicWall SMA1000 VPN Portal Audit
    (CVE-2026-93866, CVE-2026-103594, CVE-2026-121639 & CVE-2026-83548).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "WatchGuard Fireware & SonicWall SMA VPN Audit (CVE-2026-93866 / CVE-2026-83548)",
            "description": (
                "Passive version compliance check for WatchGuard Fireware OS Access Portal "
                "(CVE-2026-93866 CVSS 9.2, CVE-2026-103594 CVSS 9.5) and SonicWall SMA1000 WorkPlace "
                "(CVE-2026-83548 CVSS 10.0)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-93866",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_VPN_APPLIANCE_PORTS.copy()
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
                    or "watchguard" in s_name
                    or "sonicwall" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (443, 4100, 8080, 8443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-93866)",
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
            ("/wgcgi.cgi?action=sslvpn_logon", "WatchGuard Fireware SSL-VPN / Access Portal"),
            ("/accessportal/", "WatchGuard Fireware OS Access Portal"),
            ("/__swp__/login", "SonicWall SMA1000 WorkPlace Portal"),
        ]

        detected = False
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
                "watchguard" in combined_lower
                or "fireware" in combined_lower
                or "wgcgi.cgi" in combined_lower
                or "sonicwall" in combined_lower
                or "workplace" in combined_lower
            ):
                detected = True
                detected_source = source_label

                ver_info = parse_fireware_or_sma_version(combined)
                if ver_info:
                    vendor, major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_vpn_appliance_vulnerable(vendor, major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "WatchGuard Fireware Access Portal or SonicWall SMA WorkPlace detected, "
                    "but exact firmware build is concealed. Verify Fireware >= 12.11.4 or SMA1000 >= 12.4.3-03095."
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
                    f"- [{port_label}] Firmware {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Firmware {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-93866 / CVE-2026-83548 affected VPN appliance detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-93866 / CVE-2026-83548):\n"
                f"The target host {target_ip} runs an affected WatchGuard Fireware OS or SonicWall SMA1000 release.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-93866 (CVSS 9.2): WatchGuard Fireware Access Portal WebSocket heap overflow.\n"
                f"- CVE-2026-103594 (CVSS 9.5): WatchGuard Fireware WireGuard stack buffer overflow.\n"
                f"- CVE-2026-83548 (CVSS 10.0): SonicWall SMA1000 WorkPlace pre-auth SSRF.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade WatchGuard Fireware OS to >= 12.11.4 and SonicWall SMA1000 to >= 12.4.3-03095."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "VPN appliance portal detected (firmware concealed)."
            details = (
                f"VPN portal detected on {target_ip}; manual firmware verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: VPN appliance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected WatchGuard Fireware or SonicWall SMA1000 services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for WatchGuard Fireware & SonicWall SMA (CVE-2026-93866 / CVE-2026-83548)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_VPN_APPLIANCE_PORTS,
        help="Ports to inspect (default: 443 4100 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = WatchGuardSonicWallVpnAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a VPN firmware affected by CVE-2026-93866 / CVE-2026-83548.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes VPN services requiring firmware verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
