"""
surrealdb_cve_2026_134292_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for SurrealDB database
deployments (versions >= 1.0.0 and < 4.0.0) to verify patch compliance against
CVE-2026-134292.

CVSS Score: 9.3 (Critical)
Affected Components: SurrealDB >= 1.0.0, < 4.0.0.
Fixed in: SurrealDB 4.0.0+.

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

DEFAULT_WEB_PORTS = [8000, 8080, 443, 80, 8443]
SSL_PORTS = {443, 8443, 9443}
MIN_AFFECTED_VERSION = (1, 0, 0)
MIN_PATCHED_VERSION = (4, 0, 0)


def parse_surrealdb_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts SurrealDB semantic version (major, minor, patch, raw_str) from:
      - SurrealDB /version endpoint plain text: 'surrealdb-2.1.4', 'surrealdb-3.0.2+20261015'
      - HTTP Server / X-Surreal-Version headers: 'Server: SurrealDB/2.1.4', 'surrealdb/3.0.1'
      - JSON version payloads: '{"version": "2.1.4"}' (when paired with SurrealDB context)
    """
    if not text:
        return None

    patterns = [
        r"surrealdb[:/\s\-v]+([0-9]+)\.([0-9]+)\.([0-9]+)",
        r"x-surreal(?:-db)?-version\s*:\s*v?([0-9]+)\.([0-9]+)\.([0-9]+)",
        r"(?:surrealdb_version|version)['\"\s:=]+(?:surrealdb-)?v?([0-9]+)\.([0-9]+)\.([0-9]+)",
        r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            raw_ver = f"{major}.{minor}.{patch}"
            return major, minor, patch, raw_ver

    return None


def is_surrealdb_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a SurrealDB version tuple is affected by CVE-2026-134292 (>= 1.0.0, < 4.0.0).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if MIN_AFFECTED_VERSION <= ver_tuple < MIN_PATCHED_VERSION:
        return True, (
            f"SurrealDB {ver_str} is affected by CVE-2026-134292 "
            f"(affected: >= 1.0.0, < 4.0.0; requires upgrade to >= 4.0.0)."
        )

    return False, (
        f"SurrealDB {ver_str} is patched against CVE-2026-134292 "
        f"(running >= 4.0.0)."
    )


class SurrealDbAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: SurrealDB Embedded JS Capability Check Bypass Compliance Audit (CVE-2026-134292).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "SurrealDB Embedded JS Capability Bypass Compliance Audit (CVE-2026-134292)",
            "description": (
                "Passive version compliance check for SurrealDB 1.0.0 before 4.0.0 "
                "(CVE-2026-134292 — CVSS 9.3)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-134292",
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
                    or "surreal" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (8000, 8080, 443, 80, 8443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-134292)",
                "Accept": "application/json,text/plain,*/*",
                "Connection": "close",
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            raw_body = response.read(32768).decode("utf-8", errors="replace")

            resp_headers: Dict[str, str] = {}
            for k, v in response.getheaders():
                resp_headers[k.lower()] = v

            return {
                "port": port,
                "path": path,
                "status_code": response.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:16384],
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
            ("/version", "SurrealDB Version Endpoint"),
            ("/status", "SurrealDB Status Endpoint"),
            ("/health", "SurrealDB Health Endpoint"),
            ("/", "HTTP Root"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "").strip()
            combined = f"{headers}\n{body}"
            combined_lower = combined.lower()

            if "surrealdb" in combined_lower or "surreal" in headers.get("server", "").lower():
                ver_info = parse_surrealdb_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_surrealdb_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": f"{source_label} ({path})",
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
                    f"- [{port_label}] SurrealDB {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] SurrealDB {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated SurrealDB version detected on {target_ip} (CVE-2026-134292).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (SurrealDB 1.0.0 - < 4.0.0 - CVSS 9.3):\n"
                f"The target host {target_ip} runs an unpatched version of SurrealDB.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-134292 (CVSS 9.3): Capability check bypass in the embedded JavaScript scripting engine.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade SurrealDB to version 4.0.0 or later."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: SurrealDB instances on {target_ip} are running versions (>= 4.0.0) "
                f"compliant against CVE-2026-134292:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected SurrealDB installations detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance audit for SurrealDB (CVE-2026-134292)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[8000, 8080, 443, 80])
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    plugin = SurrealDbAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        sys.exit(0)
    res = plugin.run_audit(args.target, args.ports)
    if res.get("status") == "Vulnerable":
        print(res.get("details", ""))
        sys.exit(1)
    print(res.get("details", ""))
    sys.exit(0)
