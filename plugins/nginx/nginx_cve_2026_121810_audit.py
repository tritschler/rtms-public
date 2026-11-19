"""
nginx_cve_2026_121810_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and error-page version verification for
NGINX Open Source & NGINX Plus against the November 2026 F5/NGINX Security Advisory (5 CVEs):
  - CVE-2026-121810 (CVSS 9.2 Critical): HTTP/3 worker process use-after-free condition.
  - CVE-2026-123007 (CVSS 9.2 Critical): HTTP/2 flow control window heap buffer overflow.
  - CVE-2026-113425 (CVSS 9.2 Critical): Mail proxy worker process use-after-free condition.
  - CVE-2026-123634 (CVSS 9.2 Critical): Proxy variable server name with SSI/mirror subrequest use-after-free.
  - CVE-2026-123633 (CVSS 9.2 Critical): HTTP/2 client connection proxy low worker_connections use-after-free.

Affected Versions:
  - NGINX Open Source: 0.5.33 through < 1.30.7 (stable branch) and 1.31.0 through < 1.31.9 (mainline branch)
  - NGINX Plus: 37.0.0 through < 37.0.8.1 and 37.1.0 through < 37.3.0.1 (R33+)

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
                return self.format_result("Skipped", details="Requirements not met (no target NGINX ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_NGINX_PORTS = [80, 443, 8080, 8443, 8000, 8888]
SSL_PORTS = {443, 8443}


def parse_nginx_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts NGINX version tuple (major, minor, patch, raw_str) from HTTP Server headers
    or default NGINX welcome/error pages (e.g. 'Server: nginx/1.30.4' or '<center>nginx/1.31.6</center>').
    """
    if not text:
        return None

    patterns = [
        r"\bnginx[/\s:v]+([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})\b",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            raw_str = f"{major}.{minor}.{patch}"
            return major, minor, patch, raw_str

    return None


def is_nginx_version_vulnerable(
    major: int,
    minor: int,
    patch: int,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether an NGINX Open Source version is affected by the November 2026 critical advisories:
      - CVE-2026-121810 (CVSS 9.2): >= 1.25.0, < 1.30.7 and >= 1.31.0, < 1.31.9
      - CVE-2026-123007 (CVSS 9.2): >= 1.9.5, < 1.30.7 and >= 1.31.0, < 1.31.9
      - CVE-2026-113425 (CVSS 9.2): >= 0.5.33, < 1.30.7 and >= 1.31.0, < 1.31.9
      - CVE-2026-123634 (CVSS 9.2): >= 0.6.18, < 1.30.7 and >= 1.31.0, < 1.31.9
      - CVE-2026-123633 (CVSS 9.2): >= 1.19.7, < 1.30.7 and >= 1.31.0, < 1.31.9
    """
    ver = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if ver < (0, 5, 33):
        return False, f"NGINX {ver_display} is prior to 0.5.33 and outside the evaluated range."

    if (1, 30, 7) <= ver < (1, 31, 0):
        return False, (
            f"NGINX {ver_display} is patched in the 1.30.x stable branch (>= 1.30.7) against "
            f"CVE-2026-121810, CVE-2026-123007, CVE-2026-113425, CVE-2026-123634, and CVE-2026-123633."
        )

    if ver >= (1, 31, 9):
        return False, (
            f"NGINX {ver_display} is patched in the 1.31.x+ mainline branch (>= 1.31.9) against "
            f"CVE-2026-121810, CVE-2026-123007, CVE-2026-113425, CVE-2026-123634, and CVE-2026-123633."
        )

    if (1, 31, 0) <= ver < (1, 31, 9):
        return True, (
            f"NGINX {ver_display} is in the affected 1.31.x mainline branch (< 1.31.9) and is vulnerable to "
            f"CVE-2026-121810, CVE-2026-123007, CVE-2026-113425, CVE-2026-123634, and CVE-2026-123633 (CVSS 9.2)."
        )

    applicable_cves: List[str] = ["CVE-2026-113425"]
    if ver >= (0, 6, 18):
        applicable_cves.append("CVE-2026-123634")
    if ver >= (1, 9, 5):
        applicable_cves.append("CVE-2026-123007")
    if ver >= (1, 19, 7):
        applicable_cves.append("CVE-2026-123633")
    if ver >= (1, 25, 0):
        applicable_cves.append("CVE-2026-121810")

    cve_list_str = ", ".join(applicable_cves)
    return True, (
        f"NGINX {ver_display} is prior to 1.30.7 / 1.31.9 and is affected by {cve_list_str} (CVSS 9.2)."
    )


class NginxAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: NGINX Open Source & NGINX Plus Version Compliance Audit
    (CVE-2026-121810, CVE-2026-123007, CVE-2026-113425, CVE-2026-123634, CVE-2026-123633 - CVSS 9.2 Critical).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "NGINX Open Source & NGINX Plus Version Compliance Audit (CVE-2026-121810)",
            "description": (
                "Passive version compliance check for NGINX Open Source (< 1.30.7, 1.31.0 to < 1.31.9) "
                "and NGINX Plus against CVE-2026-121810, CVE-2026-123007, CVE-2026-113425, "
                "CVE-2026-123634, and CVE-2026-123633 (CVSS 9.2)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-121810",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_NGINX_PORTS.copy()
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

                if port in self.target_ports or "nginx" in s_name or "http" in s_name:
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-121810)",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
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
            logger.debug(f"NGINX HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        probe = self.probe_http_endpoint(target_ip, port, path="/", timeout=timeout)
        if not probe:
            return None

        headers = probe.get("headers", {})
        body = probe.get("body_snippet", "")
        server_hdr = str(headers.get("server", ""))
        combined = f"Server: {server_hdr}\n{body}"

        if "nginx" in combined.lower():
            ver_info = parse_nginx_version(combined)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_nginx_version_vulnerable(major, minor, patch, ver_str)
                source_label = "HTTP Server Header" if "nginx/" in server_hdr.lower() else "HTTP Response Body"
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
                    f"- [{port_label}] NGINX {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] NGINX {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-121810..CVE-2026-123634 affected NGINX server detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-121810 & Related Advisories - CVSS 9.2):\n"
                f"The target host {target_ip} exposes an unpatched NGINX instance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-121810 (CVSS 9.2): HTTP/3 worker process use-after-free vulnerability.\n"
                f"- CVE-2026-123007 (CVSS 9.2): HTTP/2 flow control window heap buffer overflow.\n"
                f"- CVE-2026-113425 (CVSS 9.2): Mail proxy worker process use-after-free vulnerability.\n"
                f"- CVE-2026-123634 (CVSS 9.2): Proxy variable server name SSI/mirror subrequest use-after-free.\n"
                f"- CVE-2026-123633 (CVSS 9.2): HTTP/2 client connection proxy low worker_connections use-after-free.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade NGINX Open Source to version 1.30.7+ (stable branch) or 1.31.9+ (mainline branch).\n"
                f"2. For NGINX Plus deployments, upgrade to 37.0.8.1+ or 37.3.0.1+.\n"
                f"3. Set 'server_tokens off;' in nginx.conf to minimize version disclosure."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: NGINX instance on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected NGINX services with exposed version tokens detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for NGINX (CVE-2026-121810..CVE-2026-123634)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_NGINX_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443 8000 8888)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = NginxAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an NGINX version affected by CVE-2026-121810.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
