"""
php_fpm_cve_2026_129289_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and header (X-Powered-By / Server) version
verification for PHP and PHP-FPM against the November 2026 Multi-CVE Advisory (7 CVEs):
  - CVE-2026-129289 (CVSS 9.2 Critical): PHP-FPM request smuggling through an unread HTTP request body.
  - CVE-2026-129496 (CVSS 9.2 Critical): Timezone cache use-after-free leading to worker crash or remote code execution.
  - CVE-2026-126714 (CVSS 9.2 Critical): Partially overwritten session files leading to object injection and remote code execution.
  - CVE-2026-115560 (CVSS 9.2 Critical): Session serializer mismatch leading to object injection and remote code execution.
  - CVE-2026-129481 (CVSS 9.2 Critical): Use-after-free after interrupted session shutdown.
  - CVE-2026-129474 (CVSS 9.2 Critical): Use-after-free in magic method backtraces leading to remote code execution.
  - CVE-2026-129182 (CVSS 9.2 Critical): Use-after-free via repopulation of last_fatal_error_backtrace global after shutdown.

Affected Versions:
  - PHP 8.2.x: 8.2.0 through 8.2.35 (< 8.2.36) and older EOL branches (< 8.2.0)
  - PHP 8.3.x: 8.3.0 through 8.3.36 (< 8.3.37)
  - PHP 8.4.x: 8.4.0 through 8.4.27 (< 8.4.28)
  - PHP 8.5.x: 8.5.0 through 8.5.12 (< 8.5.13)

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
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/HTTPS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8088, 8888, 9000]
SSL_PORTS = {443, 8443, 9443}


def parse_php_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts PHP version tuple (major, minor, patch, raw_str)
    from X-Powered-By, Server headers, or PHP version banners.

    Examples:
      - 'X-Powered-By: PHP/8.4.27' -> (8, 4, 27, '8.4.27')
      - 'Server: Apache/2.4.62 (Debian) PHP/8.3.35-1~deb12u1' -> (8, 3, 35, '8.3.35')
      - 'PHP 8.5.12 (fpm-fcgi)' -> (8, 5, 12, '8.5.12')
    """
    if not text:
        return None

    match = re.search(
        r"\bPHP(?:-FPM)?[\s/:-]+v?([0-9]+)\.([0-9]+)\.([0-9]+)\b",
        text,
        re.IGNORECASE,
    )
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3))
        raw_str = f"{major}.{minor}.{patch}"
        return major, minor, patch, raw_str

    return None


def is_php_version_vulnerable(
    major: int,
    minor: int,
    patch: int,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether a PHP / PHP-FPM version is affected by the November 2026
    Multi-CVE Security Advisory:
      - CVE-2026-129289, CVE-2026-129496, CVE-2026-126714, CVE-2026-115560 (8.2 < 8.2.36, 8.3 < 8.3.37, 8.4 < 8.4.28, 8.5 < 8.5.13)
      - CVE-2026-129481 (8.3 < 8.3.37, 8.4 < 8.4.28, 8.5 < 8.5.13)
      - CVE-2026-129474, CVE-2026-129182 (8.5 < 8.5.13)
    """
    ver = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if ver < (8, 2, 0):
        return True, (
            f"PHP {ver_display} is an End-of-Life release (< 8.2.0) and lacks fixes for "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-126714, and CVE-2026-115560 (CVSS 9.2)."
        )

    if (8, 2, 0) <= ver < (8, 2, 36):
        return True, (
            f"PHP {ver_display} is in the 8.2.x branch prior to 8.2.36 and is affected by "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-126714, and CVE-2026-115560 (CVSS 9.2)."
        )

    if (8, 2, 36) <= ver < (8, 3, 0):
        return False, (
            f"PHP {ver_display} is patched in the 8.2.x branch (>= 8.2.36) against "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-126714, and CVE-2026-115560."
        )

    if (8, 3, 0) <= ver < (8, 3, 37):
        return True, (
            f"PHP {ver_display} is in the 8.3.x branch prior to 8.3.37 and is affected by "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, CVE-2026-126714, and CVE-2026-115560 (CVSS 9.2)."
        )

    if (8, 3, 37) <= ver < (8, 4, 0):
        return False, (
            f"PHP {ver_display} is patched in the 8.3.x branch (>= 8.3.37) against "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, CVE-2026-126714, and CVE-2026-115560."
        )

    if (8, 4, 0) <= ver < (8, 4, 28):
        return True, (
            f"PHP {ver_display} is in the 8.4.x branch prior to 8.4.28 and is affected by "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, CVE-2026-126714, and CVE-2026-115560 (CVSS 9.2)."
        )

    if (8, 4, 28) <= ver < (8, 5, 0):
        return False, (
            f"PHP {ver_display} is patched in the 8.4.x branch (>= 8.4.28) against "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, CVE-2026-126714, and CVE-2026-115560."
        )

    if (8, 5, 0) <= ver < (8, 5, 13):
        return True, (
            f"PHP {ver_display} is in the 8.5.x branch prior to 8.5.13 and is affected by "
            f"CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, CVE-2026-129474, CVE-2026-129182, "
            f"CVE-2026-126714, and CVE-2026-115560 (CVSS 9.2)."
        )

    return False, (
        f"PHP {ver_display} is patched (>= 8.5.13) against CVE-2026-129289 and related November 2026 PHP advisories."
    )


class PhpFpmAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: PHP & PHP-FPM Multi-CVE Version Compliance Audit
    (CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, CVE-2026-129474,
    CVE-2026-129182, CVE-2026-126714, CVE-2026-115560 - CVSS 9.2 Critical).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "PHP & PHP-FPM Multi-CVE Version Compliance Audit (CVE-2026-129289)",
            "description": (
                "Passive version compliance check for PHP and PHP-FPM (8.2 < 8.2.36, 8.3 < 8.3.37, "
                "8.4 < 8.4.28, 8.5 < 8.5.13) against CVE-2026-129289, CVE-2026-129496, CVE-2026-129481, "
                "CVE-2026-129474, CVE-2026-129182, CVE-2026-126714, and CVE-2026-115560 (CVSS 9.2)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-129289",
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

                if port in self.target_ports or "http" in s_name or "php" in s_name or "web" in s_name:
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-129289)",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                "Connection": "close",
            }
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            raw_body = resp.read(8192).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return {
                "port": port,
                "path": path,
                "status_code": resp.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:4096],
            }
        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"PHP HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/", "HTTP Response Headers (X-Powered-By / Server)"),
            ("/index.php", "PHP Index Endpoint Headers"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            body = probe.get("body_snippet", "")
            combined = f"{header_text}\n{body}"

            ver_info = parse_php_version(combined)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_php_version_vulnerable(major, minor, patch, ver_str)
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
                    f"- [{port_label}] PHP {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] PHP {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-129289 & related PHP advisories: unpatched PHP version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-129289 & Related PHP Advisories - CVSS 9.2):\n"
                f"The target host {target_ip} exposes an unpatched PHP / PHP-FPM runtime.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-129289 (CVSS 9.2): PHP-FPM FastCGI request smuggling through an unread HTTP request body.\n"
                f"- CVE-2026-129496 (CVSS 9.2): Timezone cache use-after-free leading to worker crash or remote code execution.\n"
                f"- CVE-2026-126714 (CVSS 9.2): Partially overwritten session files leading to object injection and RCE.\n"
                f"- CVE-2026-115560 (CVSS 9.2): Session serializer mismatch leading to object injection and RCE.\n"
                f"- CVE-2026-129481 (CVSS 9.2): Use-after-free after interrupted session shutdown.\n"
                f"- CVE-2026-129474 (CVSS 9.2): Use-after-free in magic method backtraces leading to RCE.\n"
                f"- CVE-2026-129182 (CVSS 9.2): Use-after-free via repopulation of last_fatal_error_backtrace after shutdown.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade PHP to version 8.2.36+, 8.3.37+, 8.4.28+, or 8.5.13+.\n"
                f"2. Disable expose_php in php.ini to avoid exposing runtime version headers."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: PHP runtime on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected PHP / PHP-FPM version banners detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for PHP & PHP-FPM (CVE-2026-129289 & 6 related CVEs)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_WEB_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443 8000 8088 8888 9000)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = PhpFpmAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a PHP version affected by CVE-2026-129289.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
