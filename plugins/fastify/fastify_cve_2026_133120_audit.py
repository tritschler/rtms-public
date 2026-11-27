"""
fastify_cve_2026_133120_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS and manifest metadata version verification for
Node.js Fastify deployments using @fastify/express (< 4.0.14) or @fastify/middie (<= 9.3.7)
to verify patch compliance against CVE-2026-135279, CVE-2026-133120, CVE-2026-129504,
CVE-2026-133867, CVE-2026-124626, and CVE-2026-133250.

CVSS Score: 9.1 (Critical)
Affected Components:
  - @fastify/express < 4.0.14 (CVE-2026-135279; < 4.0.10 also affected by CVE-2026-133120, CVE-2026-129504, CVE-2026-133867, CVE-2026-124626)
  - @fastify/middie <= 9.3.7 (< 9.3.8) (CVE-2026-133250)
Fixed in:
  - @fastify/express 4.0.14+
  - @fastify/middie 9.3.8+

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

DEFAULT_WEB_PORTS = [3000, 8080, 8000, 443, 80, 8443]
SSL_PORTS = {443, 8443, 9443}
MIN_PATCHED_FASTIFY_EXPRESS = (4, 0, 14)
MIN_PATCHED_FASTIFY_MIDDIE = (9, 3, 8)


def parse_fastify_middleware_version(text: str) -> Optional[Tuple[str, int, int, int, str]]:
    """
    Extracts (@fastify/express or @fastify/middie, major, minor, patch, raw_str) from:
      - HTTP response headers or JSON diagnostic endpoints: '@fastify/express/4.0.9', '@fastify/middie@9.3.7'
      - Package manifests / lockfile snippets: '"@fastify/express": "^4.0.8"', '"@fastify/middie": "9.3.7"'
    """
    if not text:
        return None

    patterns = [
        (
            "@fastify/express",
            r"@fastify/express['\"\s:/@=]+[\^~v]*([0-9]+)\.([0-9]+)\.([0-9]+)",
        ),
        (
            "@fastify/middie",
            r"@fastify/middie['\"\s:/@=]+[\^~v]*([0-9]+)\.([0-9]+)\.([0-9]+)",
        ),
        (
            "@fastify/express",
            r"node_modules/@fastify/express['\"][^}]*?['\"]version['\"]\s*:\s*['\"]([0-9]+)\.([0-9]+)\.([0-9]+)['\"]",
        ),
        (
            "@fastify/middie",
            r"node_modules/@fastify/middie['\"][^}]*?['\"]version['\"]\s*:\s*['\"]([0-9]+)\.([0-9]+)\.([0-9]+)['\"]",
        ),
    ]

    for pkg_name, pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            raw_ver = f"{major}.{minor}.{patch}"
            return pkg_name, major, minor, patch, raw_ver

    return None


def is_fastify_middleware_version_vulnerable(
    package_name: str, major: int, minor: int, patch: int
) -> Tuple[bool, str]:
    """
    Evaluates whether a @fastify/express or @fastify/middie version tuple is affected by
    CVE-2026-133120 / CVE-2026-129504 / CVE-2026-133867 / CVE-2026-124626 / CVE-2026-133250.
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"
    pkg = package_name.lower().strip()

    if pkg == "@fastify/express":
        if ver_tuple < MIN_PATCHED_FASTIFY_EXPRESS:
            cves = ["CVE-2026-135279"]
            if ver_tuple < (4, 0, 10):
                cves.append("CVE-2026-133120")
            if (4, 0, 0) <= ver_tuple <= (4, 0, 9):
                cves.append("CVE-2026-129504")
            if (4, 0, 5) <= ver_tuple <= (4, 0, 9):
                cves.append("CVE-2026-124626")
            if (4, 0, 7) <= ver_tuple <= (4, 0, 9):
                cves.append("CVE-2026-133867")
            cve_list = ", ".join(cves)
            return True, (
                f"@fastify/express {ver_str} is affected by {cve_list} "
                f"(affected: < 4.0.14; requires upgrade to >= 4.0.14)."
            )
        return False, (
            f"@fastify/express {ver_str} is patched against CVE-2026-135279, CVE-2026-133120, "
            f"CVE-2026-129504, CVE-2026-133867, and CVE-2026-124626 (running >= 4.0.14)."
        )

    if pkg == "@fastify/middie":
        if ver_tuple < MIN_PATCHED_FASTIFY_MIDDIE:
            return True, (
                f"@fastify/middie {ver_str} is affected by CVE-2026-133250 "
                f"(affected: <= 9.3.7 (< 9.3.8); requires upgrade to >= 9.3.8)."
            )
        return False, (
            f"@fastify/middie {ver_str} is patched against CVE-2026-133250 "
            f"(running >= 9.3.8)."
        )

    return False, f"Unrecognized package {package_name} {ver_str}."


class FastifyMiddlewareAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Fastify Middleware (@fastify/express & @fastify/middie) Multi-CVE Compliance Audit
    (CVE-2026-133120, CVE-2026-129504, CVE-2026-133867, CVE-2026-124626, CVE-2026-133250).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Fastify Middleware (@fastify/express & @fastify/middie) Multi-CVE Audit (CVE-2026-135279 / CVE-2026-133120)",
            "description": (
                "Passive version compliance check for @fastify/express < 4.0.14 and @fastify/middie <= 9.3.7 "
                "(CVE-2026-135279, CVE-2026-133120, CVE-2026-129504, CVE-2026-133867, CVE-2026-124626, CVE-2026-133250 — CVSS 9.1)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-135279, CVE-2026-133120, CVE-2026-129504, CVE-2026-133867, CVE-2026-124626, CVE-2026-133250",
            "version": "1.1.0",
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
                    or "node" in s_name
                    or "fastify" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (3000, 8080, 8000, 443, 80, 8443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-133120)",
                "Accept": "application/json,text/plain,text/html,*/*",
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
            ("/version", "Fastify Version Endpoint"),
            ("/health", "Fastify Health / Metadata Endpoint"),
            ("/package.json", "Exposed Application Manifest"),
            ("/", "HTTP Root"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            ver_info = parse_fastify_middleware_version(combined)
            if ver_info:
                pkg_name, major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_fastify_middleware_version_vulnerable(pkg_name, major, minor, patch)
                return {
                    "port": port,
                    "service_detected": True,
                    "package": pkg_name,
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
            pkg = result.get("package", "@fastify/express")
            ver = result.get("version", "")
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] {pkg} {ver} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] {pkg} {ver} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated Fastify middleware version detected on {target_ip} "
                f"(CVE-2026-133120 / CVE-2026-133250).\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (Fastify Middleware - CVSS 9.1):\n"
                f"The target host {target_ip} exposes an unpatched version of @fastify/express or @fastify/middie.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-133120 / CVE-2026-129504 / CVE-2026-133867 / CVE-2026-124626 (CVSS 9.1): "
                f"Path-scoped middleware routing desynchronization and bypass in @fastify/express < 4.0.10.\n"
                f"- CVE-2026-133250 (CVSS 9.1): Path-scoped middleware routing mismatch in @fastify/middie <= 9.3.7.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade @fastify/express to version 4.0.10 or later.\n"
                f"2. Upgrade @fastify/middie to version 9.3.8 or later."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Fastify middleware packages on {target_ip} are running versions compliant against "
                f"CVE-2026-133120, CVE-2026-129504, CVE-2026-133867, CVE-2026-124626, and CVE-2026-133250:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected @fastify/express or @fastify/middie versions detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance audit for Fastify Middleware (CVE-2026-133120 / CVE-2026-133250)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[3000, 8080, 8000, 443, 80])
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    plugin = FastifyMiddlewareAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        sys.exit(0)
    res = plugin.run_audit(args.target, args.ports)
    if res.get("status") == "Vulnerable":
        print(res.get("details", ""))
        sys.exit(1)
    print(res.get("details", ""))
    sys.exit(0)
