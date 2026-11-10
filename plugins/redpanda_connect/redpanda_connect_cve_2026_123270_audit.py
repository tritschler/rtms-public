"""
redpanda_connect_cve_2026_123270_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version and management API exposure
verification for Redpanda Connect servers (versions 4.39 to 4.110) to check
patch compliance for CVE-2026-123270.

CVSS Score: 9.8 (Critical) - CWE-306 (Missing Authentication for Critical Function)
Affected Components: Redpanda Connect 4.39.0 through 4.110.x (< 4.111.0).
Fixed in: Redpanda Connect 4.111.0+.

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
                return self.format_result("Skipped", details="Requirements not met (no target Redpanda Connect HTTP ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# 4195 is the default Redpanda Connect / Benthos HTTP admin port
DEFAULT_REDPANDA_PORTS = [4195, 8080, 80, 443, 8443]
SSL_PORTS = {443, 8443, 9443}

MIN_AFFECTED_VERSION = (4, 39, 0)
MIN_PATCHED_VERSION = (4, 111, 0)


def parse_redpanda_connect_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Redpanda Connect semantic version (major, minor, patch, raw_str) from:
      - /version JSON response: '{"version":"v4.105.0","built":"2026-10-15T..."}' or '{"version":"4.98.0"}'
      - HTTP headers or banner text: 'Redpanda Connect v4.102.1' or 'redpanda-connect/4.85.0'
    """
    if not text:
        return None

    patterns = [
        r"[\"']version[\"']\s*:\s*[\"']v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?[\"']",
        r"(?:redpanda[\s_-]*connect|benthos)[/\s:v]+([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"^v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            raw_ver = f"{major}.{minor}.{patch}" if match.group(3) is not None else f"{major}.{minor}"
            return major, minor, patch, raw_ver

    return None


def is_redpanda_connect_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Redpanda Connect version tuple (major, minor, patch) is affected
    by CVE-2026-123270 (4.39.0 <= version < 4.111.0).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if MIN_AFFECTED_VERSION <= ver_tuple < MIN_PATCHED_VERSION:
        return True, (
            f"Redpanda Connect {ver_str} is affected by CVE-2026-123270 "
            f"(affected: 4.39.0 to 4.110.x; requires upgrade to >= 4.111.0)."
        )

    return False, (
        f"Redpanda Connect {ver_str} is not in the default-vulnerable range for CVE-2026-123270 "
        f"(patched in >= 4.111.0)."
    )


class RedpandaConnectAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Redpanda Connect Version Compliance Audit (CVE-2026-123270).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Redpanda Connect Version Compliance Audit (CVE-2026-123270)",
            "description": (
                "Passive version and API exposure compliance check for Redpanda Connect "
                "versions 4.39 to 4.110 (CVE-2026-123270)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-123270",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_REDPANDA_PORTS.copy()
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
                    or "redpanda" in s_name
                    or "benthos" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (4195, 80, 443, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/version",
        timeout: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        use_ssl = port in SSL_PORTS or port in (443, 8443, 9443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-123270)",
                "Accept": "application/json,text/plain,*/*",
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
            ("/version", "Redpanda Connect /version endpoint"),
            ("/endpoints", "Redpanda Connect /endpoints route catalog"),
        ]

        service_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe or probe.get("status_code") != 200:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            combined = f"{server_hdr}\n{body}"
            combined_lower = combined.lower()

            is_redpanda_connect = (
                ("version" in combined_lower and "built" in combined_lower)
                or "redpanda connect" in combined_lower
                or "redpanda-connect" in combined_lower
                or "/streams" in combined_lower
                or ("/ready" in combined_lower and "/ping" in combined_lower)
            )

            if is_redpanda_connect:
                service_detected = True
                detected_source = f"{source_label} (HTTP 200 response)"

                ver_info = parse_redpanda_connect_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_redpanda_connect_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if service_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Redpanda Connect management HTTP API is active on this port, but its exact "
                    "version string is concealed. Verify that the deployment runs >= 4.111.0 and "
                    "that the HTTP management interface is not exposed without authentication."
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
                    f"- [{port_label}] Redpanda Connect {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Redpanda Connect {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-123270 affected Redpanda Connect version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-123270 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an affected version of Redpanda Connect (4.39 to 4.110).\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Redpanda Connect to version 4.111.0 or later.\n"
                f"2. Do not expose the HTTP administration API (TCP 4195) on untrusted network interfaces "
                f"or enable `--bind-http` without authentication."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Redpanda Connect HTTP API active with concealed version string."
            details = (
                f"Redpanda Connect HTTP API detected on {target_ip}, but version metadata is concealed:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Redpanda Connect instances on {target_ip} are running patched versions (>= 4.111.0):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Redpanda Connect HTTP services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Redpanda Connect (CVE-2026-123270)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_REDPANDA_PORTS,
        help="Ports to inspect (default: 4195 8080 80 443 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = RedpandaConnectAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an affected Redpanda Connect version (CVE-2026-123270).\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} requires manual Redpanda Connect verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
