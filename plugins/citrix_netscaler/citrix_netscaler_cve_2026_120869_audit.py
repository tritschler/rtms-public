"""
citrix_netscaler_cve_2026_120869_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and portal metadata verification for
Citrix NetScaler Console / NetScaler ADC & Gateway appliances against:
  - CVE-2026-120869 (CVSS 9.3 Critical): Unauthenticated authentication bypass allowing
    access to restricted administrative resources on Citrix NetScaler Console appliances.

Affected Versions:
  - Citrix NetScaler Console / ADM 14.1 prior to 14.1-38.53 (Fixed in 14.1-38.53+)
  - Citrix NetScaler Console / ADM 13.1 prior to 13.1-56.18 (Fixed in 13.1-56.18+)

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
                return self.format_result("Skipped", details="Requirements not met (no target Citrix NetScaler ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_NETSCALER_PORTS = [443, 8443, 9443, 80]
SSL_PORTS = {443, 8443, 9443}


def parse_netscaler_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts Citrix NetScaler version tuple (major, minor, build, subbuild, raw_str)
    from NetScaler Console / Gateway metadata (e.g. 'NS14.1-34.42' or '13.1-52.19').
    """
    if not text:
        return None

    patterns = [
        r"(?:NS|NetScaler(?:\s+Console)?|Build|v)\s*([1][34])\.([0-9]+)[-_.]([0-9]{1,3})\.([0-9]{1,3})",
        r"\b([1][34])\.([0-9]+)-([0-9]{1,3})\.([0-9]{1,3})\b",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            build = int(match.group(3))
            subbuild = int(match.group(4))
            ver_str = f"{major}.{minor}-{build}.{subbuild}"
            return major, minor, build, subbuild, ver_str

    return None


def is_netscaler_version_vulnerable(major: int, minor: int, build: int, subbuild: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Citrix NetScaler Console version is affected by CVE-2026-120869 (CVSS 9.3).
      - 14.1 < 14.1-38.53 -> Vulnerable
      - 13.1 < 13.1-56.18 -> Vulnerable
    """
    ver_str = f"{major}.{minor}-{build}.{subbuild}"

    if (major, minor) == (14, 1):
        if (build, subbuild) < (38, 53):
            return True, (
                f"Citrix NetScaler Console {ver_str} is prior to 14.1-38.53 and is affected by "
                f"CVE-2026-120869 (CVSS 9.3 Authentication Bypass)."
            )
        return False, f"Citrix NetScaler Console {ver_str} is patched (>= 14.1-38.53) against CVE-2026-120869."

    if (major, minor) == (13, 1):
        if (build, subbuild) < (56, 18):
            return True, (
                f"Citrix NetScaler Console {ver_str} is prior to 13.1-56.18 and is affected by "
                f"CVE-2026-120869 (CVSS 9.3 Authentication Bypass)."
            )
        return False, f"Citrix NetScaler Console {ver_str} is patched (>= 13.1-56.18) against CVE-2026-120869."

    return False, f"Citrix NetScaler {ver_str} is outside the affected 13.1 / 14.1 branches."


class CitrixNetScalerAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Citrix NetScaler Console Version Compliance Audit (CVE-2026-120869).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Citrix NetScaler Console Auth Bypass Audit (CVE-2026-120869)",
            "description": (
                "Passive version compliance check for Citrix NetScaler Console & Gateway appliances "
                "against CVE-2026-120869 (CVSS 9.3 Unauthenticated Authentication Bypass)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-120869",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_NETSCALER_PORTS.copy()
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
                    or "citrix" in s_name
                    or "netscaler" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 8443, 9443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/admin_ui/",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-120869)",
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
            ("/admin_ui/", "Citrix NetScaler Console /admin_ui/ portal"),
            ("/logon/LogonPoint/index.html", "Citrix NetScaler LogonPoint portal"),
            ("/vpn/index.html", "Citrix NetScaler Gateway /vpn/index.html"),
        ]

        netscaler_detected = False
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
                "netscaler" in combined_lower
                or "citrix" in combined_lower
                or "nsc_aaac" in combined_lower
                or "nsc_esns" in combined_lower
                or "logonpoint" in combined_lower
            ):
                netscaler_detected = True
                detected_source = source_label

                ver_info = parse_netscaler_version(combined)
                if ver_info:
                    major, minor, build, subbuild, ver_str = ver_info
                    is_vuln, reason = is_netscaler_version_vulnerable(major, minor, build, subbuild)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if netscaler_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Citrix NetScaler Console / Gateway interface is active, but exact firmware build is concealed. "
                    "Verify build >= 14.1-38.53 or >= 13.1-56.18 for CVE-2026-120869 compliance."
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
                    f"- [{port_label}] Citrix NetScaler {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Citrix NetScaler {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-120869 affected Citrix NetScaler Console version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-120869 - CVSS 9.3):\n"
                f"The target host {target_ip} runs an affected Citrix NetScaler Console appliance build.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-120869 (CVSS 9.3): Unauthenticated authentication bypass allowing access to restricted "
                f"resources on Citrix NetScaler Console.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Citrix NetScaler Console to >= 14.1-38.53 or >= 13.1-56.18.\n"
                f"2. Restrict management plane access (/admin_ui/) to dedicated administrative jump hosts."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Citrix NetScaler service detected (firmware build concealed)."
            details = (
                f"Citrix NetScaler service detected on {target_ip}; manual build verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Citrix NetScaler instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Citrix NetScaler Console services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Citrix NetScaler Console (CVE-2026-120869)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_NETSCALER_PORTS,
        help="Ports to inspect (default: 443 8443 9443 80)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = CitrixNetScalerAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Citrix NetScaler version affected by CVE-2026-120869.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes Citrix NetScaler services requiring build verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
