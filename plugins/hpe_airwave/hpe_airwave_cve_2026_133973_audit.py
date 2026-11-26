"""
hpe_airwave_cve_2026_133973_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS login page and management banner version verification
for HPE Networking Management Software (AirWave) against the November 2026 Security Advisories (3 CVEs):
  - CVE-2026-133973 (CVSS 9.8 Critical): Unauthenticated command injection in the web-based management interface.
  - CVE-2026-133972 (CVSS 9.8 Critical): Network authentication bypass in system functionality.
  - CVE-2026-133971 (CVSS 9.8 Critical): Unauthenticated authentication bypass in the web management interface.

Affected Versions:
  - HPE Networking Management Software (AirWave) 8.3.0.0 through 8.3.0.7 (< 8.3.0.8)

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
                return self.format_result("Skipped", details="Requirements not met (no target AirWave ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_AIRWAVE_PORTS = [443, 8443, 80, 8080]
SSL_PORTS = {443, 8443, 9443}
MIN_PATCHED_VERSION = (8, 3, 0, 8)


def parse_hpe_airwave_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts HPE AirWave version tuple (v1, v2, v3, v4, raw_str)
    from AirWave web management login pages, XML/JSON metadata, or headers.

    Examples:
      - 'HPE Networking Management Software (AirWave) 8.3.0.7' -> (8, 3, 0, 7, '8.3.0.7')
      - 'AirWave Management Platform 8.3.0.5' -> (8, 3, 0, 5, '8.3.0.5')
      - '<amp_version>8.3.0.8</amp_version>' -> (8, 3, 0, 8, '8.3.0.8')
    """
    if not text:
        return None

    patterns = [
        r"(?:AirWave(?:\s+Management\s+Platform|\s+Glass)?|HPE\s+Networking\s+Management\s+Software(?:\s*\(AirWave\))?)[^0-9\r\n]{1,40}\b([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b",
        r"(?:<amp_version>|amp_version[\s:=\"']+|\"amp_version\"\s*:\s*\")\s*v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            v1 = int(match.group(1))
            v2 = int(match.group(2))
            v3 = int(match.group(3))
            v4 = int(match.group(4)) if match.group(4) is not None else 0
            raw_str = f"{v1}.{v2}.{v3}.{v4}" if match.group(4) is not None else f"{v1}.{v2}.{v3}"
            return v1, v2, v3, v4, raw_str

    return None


def is_hpe_airwave_version_vulnerable(
    v1: int,
    v2: int,
    v3: int,
    v4: int = 0,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether an HPE AirWave version is affected by:
      - CVE-2026-133971 (CVSS 9.8)
      - CVE-2026-133972 (CVSS 9.8)
      - CVE-2026-133973 (CVSS 9.8)
    Affected: 8.3.0.0 through 8.3.0.7 (and earlier unpatched < 8.3.0.8).
    """
    ver = (v1, v2, v3, v4)
    ver_display = raw_str or f"{v1}.{v2}.{v3}.{v4}"

    if ver < MIN_PATCHED_VERSION:
        return True, (
            f"HPE Networking Management Software (AirWave) {ver_display} is prior to 8.3.0.8 "
            f"(affected range: <= 8.3.0.7) and is affected by CVE-2026-133971, CVE-2026-133972, "
            f"and CVE-2026-133973 (CVSS 9.8 Critical)."
        )

    return False, (
        f"HPE Networking Management Software (AirWave) {ver_display} is patched (>= 8.3.0.8) "
        f"against CVE-2026-133971, CVE-2026-133972, and CVE-2026-133973."
    )


class HPEAirWaveAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: HPE Networking Management Software (AirWave) Multi-CVE Compliance Audit
    (CVE-2026-133971, CVE-2026-133972, CVE-2026-133973).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "HPE Aruba AirWave Management Platform Compliance Audit (CVE-2026-133973 / CVE-2026-133971)",
            "description": (
                "Passive version compliance check for HPE Networking Management Software (AirWave) "
                "8.3.0.0–8.3.0.7 (< 8.3.0.8) against CVE-2026-133973, CVE-2026-133972, and CVE-2026-133971 (CVSS 9.8)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-133973",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_AIRWAVE_PORTS.copy()
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

                if port in self.target_ports or "airwave" in s_name or "http" in s_name or "ssl" in s_name:
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports:
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/LOGIN",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-133973)",
                "Accept": "text/html,application/xhtml+xml,application/xml,application/json,*/*",
                "Connection": "close",
            }
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            raw_body = resp.read(16384).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return {
                "port": port,
                "path": path,
                "status_code": resp.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:8192],
            }
        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"HPE AirWave HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/LOGIN", "HPE AirWave Web Login Page"),
            ("/", "HTTP Root Banner / Headers"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            if "airwave" in combined.lower() or "amp_version" in combined.lower():
                ver_info = parse_hpe_airwave_version(combined)
                if ver_info:
                    v1, v2, v3, v4, ver_str = ver_info
                    is_vuln, reason = is_hpe_airwave_version_vulnerable(v1, v2, v3, v4, ver_str)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": source_label,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("service_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] HPE AirWave {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] HPE AirWave {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-133971 / CVE-2026-133972 / CVE-2026-133973 affected HPE AirWave detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-133971, CVE-2026-133972, CVE-2026-133973 - CVSS 9.8):\n"
                f"The target host {target_ip} exposes an unpatched HPE Networking Management Software (AirWave) instance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-133973 (CVSS 9.8): Command injection in the web-based management interface.\n"
                f"- CVE-2026-133972 (CVSS 9.8): Authentication bypass in system functionality.\n"
                f"- CVE-2026-133971 (CVSS 9.8): Authentication bypass in the web management interface.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade HPE Networking Management Software (AirWave) to version 8.3.0.8 or later.\n"
                f"2. Restrict management interface access to dedicated administrative networks."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: HPE AirWave instance on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected HPE AirWave services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for HPE AirWave (CVE-2026-133971..CVE-2026-133973)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_AIRWAVE_PORTS,
        help="Ports to inspect (default: 443 8443 80 8080)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = HPEAirWaveAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an HPE AirWave version affected by CVE-2026-133973.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
