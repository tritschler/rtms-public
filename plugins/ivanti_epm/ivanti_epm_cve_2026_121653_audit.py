"""
ivanti_epm_cve_2026_121653_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and version metadata verification
for Ivanti Endpoint Manager (EPM) Core servers to check patch compliance against:
  - CVE-2026-121653 (CVSS 9.8 Critical): SQL injection vulnerability in the Core
    of Ivanti Endpoint Manager prior to version 2024 SU8.
  - CVE-2026-121683 (CVSS 9.4 Critical): Missing authentication in Ivanti Cloud
    Services Application (CSA) 5.0.8 regarding EPM Core certificate management.

Affected Versions:
  - Ivanti Endpoint Manager (EPM) prior to 2024 SU8 (< 11.0.6.8), including
    EPM 2024 SU0 through SU7 and EPM 2022.x (11.0.5.x).
  - Fixed in: Ivanti Endpoint Manager 2024 SU8 (11.0.6.8) and later.

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
                return self.format_result("Skipped", details="Requirements not met (no target Ivanti EPM ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_EPM_PORTS = [443, 80, 8443, 9593, 9594, 9595]
SSL_PORTS = {443, 8443, 9593, 9594, 9595}


def parse_ivanti_epm_version(text: str) -> Optional[Tuple[int, int, str]]:
    """
    Extracts Ivanti Endpoint Manager (EPM) release year and Service Update (SU) level
    from HTTP response headers or web portal HTML.
    Returns (release_year, su_level, display_str).
    Examples:
      - 'Ivanti Endpoint Manager 2024 SU6' -> (2024, 6, '2024 SU6')
      - 'Ivanti Endpoint Manager 2024 SU8' -> (2024, 8, '2024 SU8')
      - 'Version: 11.0.6.5'                -> (2024, 5, '2024 SU5 (11.0.6.5)')
      - 'Version: 11.0.5.4'                -> (2022, 4, '2022 SU4 (11.0.5.4)')
    """
    if not text:
        return None

    su_match = re.search(
        r"(?:Ivanti\s+)?Endpoint\s+Manager\s+(202[0-9])(?:\.[0-9]+)?(?:\s+SU\s*([0-9]+))?",
        text,
        re.IGNORECASE,
    )
    if su_match:
        year = int(su_match.group(1))
        su_raw = su_match.group(2)
        su = int(su_raw) if su_raw is not None else 0
        display = f"{year} SU{su}" if su_raw is not None else f"{year} (SU0)"
        return year, su, display

    build_match = re.search(
        r"\b(11\.0\.([56])\.([0-9]+))(?:\.[0-9]+)?\b",
        text,
    )
    if build_match:
        full_build = build_match.group(1)
        minor_branch = int(build_match.group(2))
        su = int(build_match.group(3))
        year = 2024 if minor_branch == 6 else 2022
        return year, su, f"{year} SU{su} ({full_build})"

    return None


def is_ivanti_epm_version_vulnerable(year: int, su_level: int) -> Tuple[bool, str]:
    """
    Evaluates whether an Ivanti Endpoint Manager release (year, su_level) is affected
    by CVE-2026-121653 (fixed in 2024 SU8 / 11.0.6.8).
    """
    if year < 2024:
        return True, (
            f"Ivanti Endpoint Manager {year} SU{su_level} is prior to 2024 SU8 and is affected "
            f"by CVE-2026-121653 (CVSS 9.8). Upgrade to EPM 2024 SU8 or later."
        )

    if year == 2024 and su_level < 8:
        return True, (
            f"Ivanti Endpoint Manager 2024 SU{su_level} is prior to 2024 SU8 and is affected "
            f"by CVE-2026-121653 (CVSS 9.8). Apply Service Update 8 (2024 SU8) or later."
        )

    return False, (
        f"Ivanti Endpoint Manager {year} SU{su_level} meets or exceeds the minimum patched "
        f"release (>= 2024 SU8) for CVE-2026-121653."
    )


class IvantiEpmAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Ivanti Endpoint Manager Compliance Audit (CVE-2026-121653).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Ivanti Endpoint Manager Version Compliance Audit (CVE-2026-121653)",
            "description": (
                "Passive version compliance check for Ivanti Endpoint Manager (EPM) Core "
                "servers against CVE-2026-121653 (CVSS 9.8) and CVE-2026-121683 (CVSS 9.4)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-121653",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_EPM_PORTS.copy()
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
                    or "ivanti" in s_name
                    or "landesk" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 8443, 9593, 9594, 9595):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/remote/",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-121653)",
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
            ("/remote/", "Ivanti EPM Web Console (/remote/)"),
            ("/ldlogon/", "Ivanti EPM LDLogon endpoint"),
            ("/mydevices/", "Ivanti EPM MyDevices portal"),
            ("/", "Ivanti EPM root HTTP response"),
        ]

        epm_detected = False
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
                "ivanti endpoint manager" in combined_lower
                or "landesk management suite" in combined_lower
                or "ldlogon" in combined_lower
                or ("ivanti" in combined_lower and "endpoint manager" in combined_lower)
            ):
                epm_detected = True
                detected_source = source_label

                ver_info = parse_ivanti_epm_version(combined)
                if ver_info:
                    year, su_level, ver_str = ver_info
                    is_vuln, reason = is_ivanti_epm_version_vulnerable(year, su_level)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if epm_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Ivanti Endpoint Manager (EPM) service is active, but the exact Service Update (SU) "
                    "version is concealed in unauthenticated responses. Verify that EPM 2024 SU8 (11.0.6.8) is installed."
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
                    f"- [{port_label}] Ivanti EPM {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Ivanti EPM {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-121653 affected Ivanti Endpoint Manager version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-121653 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an affected Ivanti Endpoint Manager (EPM) release.\n\n"
                f"Associated Ivanti Advisories:\n"
                f"- CVE-2026-121653 (CVSS 9.8): SQL injection in the Core of Ivanti Endpoint Manager (< 2024 SU8).\n"
                f"- CVE-2026-121683 (CVSS 9.4): Missing authentication in Ivanti Cloud Services Application (CSA 5.0.8).\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Apply Ivanti Endpoint Manager 2024 Service Update 8 (2024 SU8 / build 11.0.6.8+).\n"
                f"2. Restrict network access to EPM Core administrative web and soap endpoints to trusted internal subnets.\n"
                f"3. Ensure paired Ivanti Cloud Services Application (CSA) instances are updated beyond 5.0.8."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Ivanti Endpoint Manager service detected with concealed version banner."
            details = (
                f"Ivanti EPM service detected on {target_ip}, but exact Service Update level is concealed:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Ivanti Endpoint Manager instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Ivanti Endpoint Manager HTTP services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Ivanti Endpoint Manager (CVE-2026-121653)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_EPM_PORTS,
        help="Ports to inspect (default: 443 80 8443 9593 9594 9595)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = IvantiEpmAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an Ivanti EPM version affected by CVE-2026-121653.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} requires manual Ivanti EPM Service Update verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
