"""
postgres_enterprise_manager_cve_2026_132660_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for EDB Postgres
Enterprise Manager (PEM) deployments (versions < 10.6.1) to check patch compliance
against:
  - CVE-2026-132660 (CVSS 9.4): SECURITY DEFINER functions in the pem schema of
    the PEM backend database owned by a superuser without a fixed search_path.
  - CVE-2026-132659 (CVSS 9.4): Row-level security policies on pem.job and
    pem.jobstep do not restrict a PEM agent to its own jobs.
  - CVE-2026-132658 (CVSS 9.4): The pem_agent role inherited by PEM agent logins
    is a member of pg_read_server_files and pg_write_server_files on the backend DB.

Fixed in: EDB Postgres Enterprise Manager (PEM) 10.6.1+.

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
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/PEM services found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_PEM_PORTS = [8443, 8444, 443, 80, 5050, 8080, 9443]
SSL_PORTS = {443, 8443, 8444, 9443}
MIN_PATCHED_VERSION = (10, 6, 1)


def parse_pem_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Postgres Enterprise Manager (PEM) semantic version (major, minor, patch, raw_str) from:
      - PEM / pgAdmin-based integer asset query parameters: /pem/...?ver=100600 -> (10, 6, 0, '10.6.0')
      - Dotted asset query parameters: /pem/...?ver=10.6.0
      - HTML / JSON version metadata: 'Postgres Enterprise Manager v10.6.0', 'PEM 10.5.2', '"pem_version": "10.6.0"'
    """
    if not text:
        return None

    int_ver_match = re.search(r"/pem/[^\"'\s>]*\?ver=([1-9][0-9]{4,5})\b", text, re.IGNORECASE)
    if int_ver_match:
        ver_int = int(int_ver_match.group(1))
        major = ver_int // 10000
        minor = (ver_int % 10000) // 100
        patch = ver_int % 100
        raw_ver = f"{major}.{minor}.{patch}"
        return major, minor, patch, raw_ver

    patterns = [
        r"(?:Postgres\s+Enterprise\s+Manager|EDB\s+PEM|\bPEM\s+Server|\bPEM\s+Web)[:/\s\-v]+([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"/pem/[^\"'\s>]*\?ver=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"(?:pem_version|app_version|version_name)['\"\s:=]+v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"^v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            raw_ver = f"{major}.{minor}.{patch}"
            return major, minor, patch, raw_ver

    return None


def is_pem_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Postgres Enterprise Manager (PEM) version is affected by:
      - CVE-2026-132660, CVE-2026-132659, and CVE-2026-132658 (< 10.6.1).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if ver_tuple < MIN_PATCHED_VERSION:
        return True, (
            f"Postgres Enterprise Manager (PEM) {ver_str} is affected by CVE-2026-132660, "
            f"CVE-2026-132659, and CVE-2026-132658 (affected: < 10.6.1; requires upgrade to >= 10.6.1)."
        )

    return False, (
        f"Postgres Enterprise Manager (PEM) {ver_str} is patched against CVE-2026-132660, "
        f"CVE-2026-132659, and CVE-2026-132658 (running >= 10.6.1)."
    )


class PostgresEnterpriseManagerAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Postgres Enterprise Manager (PEM) Version Compliance Audit (CVE-2026-132660).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Postgres Enterprise Manager (PEM) Multi-CVE Compliance Audit (CVE-2026-132660)",
            "description": (
                "Passive version compliance check for EDB Postgres Enterprise Manager (PEM) < 10.6.1 "
                "(CVE-2026-132660, CVE-2026-132659, CVE-2026-132658 — CVSS 9.4)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-132660 / CVE-2026-132659 / CVE-2026-132658",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_PEM_PORTS.copy()
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
                    or "pem" in s_name
                    or "postgres" in s_name
                    or "edb" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (8443, 8444, 443, 80, 5050, 8080, 9443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/pem/login",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-132660)",
                "Accept": "text/html,application/json,text/plain,*/*",
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
            ("/pem/login", "PEM Web Login Page"),
            ("/pem/", "PEM Web Root"),
            ("/", "HTTP Root"),
        ]

        pem_detected = False
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
                "postgres enterprise manager" in combined_lower
                or "/pem/static/" in combined_lower
                or "edb pem" in combined_lower
                or "pem_version" in combined_lower
            ):
                pem_detected = True
                detected_source = f"{source_label} ({path})"

                ver_info = parse_pem_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_pem_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if pem_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Postgres Enterprise Manager (PEM) is active on this endpoint, but its exact version string "
                    "is concealed. Verify that PEM is updated to >= 10.6.1."
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
                    f"- [{port_label}] Postgres Enterprise Manager {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Postgres Enterprise Manager {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated Postgres Enterprise Manager (PEM) version detected on {target_ip} "
                f"(CVE-2026-132660 / CVE-2026-132659 / CVE-2026-132658).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (Postgres Enterprise Manager < 10.6.1 - CVSS 9.4):\n"
                f"The target host {target_ip} runs an unpatched version of EDB Postgres Enterprise Manager (PEM).\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-132660 (CVSS 9.4): SECURITY DEFINER functions in the pem schema lack a fixed search_path.\n"
                f"- CVE-2026-132659 (CVSS 9.4): Row-level security policies on pem.job and pem.jobstep do not isolate agents.\n"
                f"- CVE-2026-132658 (CVSS 9.4): Excessive pg_read_server_files / pg_write_server_files privileges assigned to pem_agent.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade EDB Postgres Enterprise Manager (PEM) server and database schema to version 10.6.1 or later.\n"
                f"2. Restrict network access to the PEM backend PostgreSQL database and web administration console."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Postgres Enterprise Manager (PEM) active with concealed version metadata."
            details = (
                f"Postgres Enterprise Manager (PEM) detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Info", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Postgres Enterprise Manager (PEM) instances on {target_ip} are running versions "
                f"(>= 10.6.1) compliant against CVE-2026-132660, CVE-2026-132659, and CVE-2026-132658:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Postgres Enterprise Manager (PEM) installations detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance audit for Postgres Enterprise Manager (CVE-2026-132660)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[8443, 8444, 443, 80, 5050])
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    plugin = PostgresEnterpriseManagerAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        sys.exit(0)
    res = plugin.run_audit(args.target, args.ports)
    if res.get("status") == "Vulnerable":
        print(res.get("details", ""))
        sys.exit(1)
    print(res.get("details", ""))
    sys.exit(0)
