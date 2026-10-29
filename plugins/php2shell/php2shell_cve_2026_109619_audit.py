"""
php2shell_cve_2026_109619_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits web services and endpoints for PHP runtime instances vulnerable to
Remote Code Execution via request-memory stale global state reuse (CVE-2026-109619 / PHP2Shell).

CVSS Score: 9.2 (Critical) - CWE-416 (Use After Free) / CWE-672 (Stale State)
Affected Components: PHP Core Engine (5.4.0 through 8.2.34, 8.3.0 through 8.3.35, 8.4.0 through 8.4.26, 8.5.0 through 8.5.11).
Fixed in: PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12.

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import socket
import ssl
import http.client
import urllib.parse
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

# Support both RTMS Scanner modular runtime and standalone CLI execution
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
                "details": details
            }

        def execute(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
            if hasattr(self, "check_requirements") and not self.check_requirements(target_ip, target_services):
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/PHP services found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Common ports serving HTTP/HTTPS/PHP applications or FastCGI
DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8088, 8888, 9000, 9443]
SSL_PORTS = {443, 8443, 9443, 4433, 10443}

# Known patched release thresholds (major, minor, minimum_patched_patch)
PATCHED_THRESHOLDS = {
    (8, 2): 35,  # PHP 8.2.35+ is safe
    (8, 3): 36,  # PHP 8.3.36+ is safe
    (8, 4): 27,  # PHP 8.4.27+ is safe
    (8, 5): 12,  # PHP 8.5.12+ is safe
}


def parse_php_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts PHP major, minor, patch version numbers from headers or response bodies.
    Examples:
      'PHP/8.3.12' -> (8, 3, 12, '8.3.12')
      'Apache/2.4.52 (Ubuntu) PHP/8.2.14-1ubuntu2' -> (8, 2, 14, '8.2.14')
    """
    if not text:
        return None

    # Matches PHP/<version> or PHP <version>
    pattern = r"(?:PHP|php)[/ ]([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[a-zA-Z0-9\.\-\_\+]*)?"
    match = re.search(pattern, text)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) is not None else 0
        raw_version = f"{major}.{minor}.{patch}"
        return major, minor, patch, raw_version

    return None


def is_php_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates PHP version tuple against CVE-2026-109619 vulnerability boundary.
    Returns (is_vulnerable, reason_description).
    """
    # PHP <= 8.1 is End-Of-Life and contains unpatched stale global state flaw
    if major < 8 or (major == 8 and minor <= 1):
        return True, (
            f"PHP {major}.{minor}.{patch} is End-of-Life (EOL) and vulnerable to CVE-2026-109619 "
            f"(stale request memory reuse RCE). No official patch exists for this branch."
        )

    # Active branches: 8.2, 8.3, 8.4, 8.5
    branch = (major, minor)
    if branch in PATCHED_THRESHOLDS:
        min_patch = PATCHED_THRESHOLDS[branch]
        if patch < min_patch:
            return True, (
                f"PHP {major}.{minor}.{patch} is vulnerable to CVE-2026-109619 "
                f"(requires >= {major}.{minor}.{min_patch})."
            )
        return False, (
            f"PHP {major}.{minor}.{patch} is patched against CVE-2026-109619 "
            f"(patched in {major}.{minor}.{min_patch}+)."
        )

    # PHP >= 8.6 or uncatalogued future releases are considered patched
    if major > 8 or (major == 8 and minor >= 6):
        return False, f"PHP {major}.{minor}.{patch} is newer than affected releases (safe)."

    return False, f"PHP {major}.{minor}.{patch} status could not be conclusively flagged."


class PHP2ShellAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: PHP Core Stale Global State RCE Audit (CVE-2026-109619 / PHP2Shell).
    Audits HTTP, HTTPS and FastCGI endpoints to detect vulnerable PHP engine versions
    capable of arbitrary code execution through worker process request memory reuse.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "PHP Core Stale Global State RCE Audit (CVE-2026-109619)",
            "description": "Audits HTTP/HTTPS and FastCGI endpoints for PHP runtime instances vulnerable to remote code execution via request-memory stale global state reuse (CVE-2026-109619 / PHP2Shell).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-109619",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_WEB_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers web, HTTP, HTTPS, or PHP service ports on the target host.
        """
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

                # Match common HTTP/PHP ports or names
                if (
                    port in self.target_ports
                    or "http" in s_name
                    or "web" in s_name
                    or "php" in s_name
                    or "fastcgi" in s_name
                    or "fcgi" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 8080, 8443):
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
        use_ssl: Optional[bool] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Safely probes an HTTP/HTTPS endpoint and extracts PHP runtime headers and signatures.
        """
        if use_ssl is None:
            use_ssl = port in SSL_PORTS or port == 443 or port == 8443 or port == 9443
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-109619)",
                "Accept": "*/*",
                "Connection": "close"
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()

            # Read up to 8KB of response body for PHP banners or error markers
            raw_body = response.read(8192).decode("utf-8", errors="replace")

            # Collect relevant headers (combining multiple headers with the same name such as Set-Cookie)
            resp_headers: Dict[str, str] = {}
            for k, v in response.getheaders():
                k_low = k.lower()
                if k_low in resp_headers:
                    resp_headers[k_low] = f"{resp_headers[k_low]}; {v}"
                else:
                    resp_headers[k_low] = v

            return {
                "port": port,
                "status_code": response.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:1024]
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
        """
        Probes standard endpoints on a port to detect and fingerprint PHP runtime instances.
        """
        # 1. Probe root path
        used_ssl: Optional[bool] = None
        probe_res = self.probe_http_endpoint(target_ip, port, path="/", timeout=timeout)
        if not probe_res:
            # Try HTTPS if HTTP failed on generic high ports
            if port not in SSL_PORTS:
                probe_res = self.probe_http_endpoint(target_ip, port, path="/", timeout=timeout, use_ssl=True)
                if probe_res:
                    used_ssl = True

        # 2. If root gave no PHP signatures, probe /index.php
        php_signature_found = False
        if probe_res:
            headers = probe_res.get("headers", {})
            if "x-powered-by" in headers or "phpsessid" in headers.get("set-cookie", "").lower():
                php_signature_found = True

        if not php_signature_found:
            if used_ssl is not None:
                probe_php = self.probe_http_endpoint(target_ip, port, path="/index.php", timeout=timeout, use_ssl=used_ssl)
            else:
                probe_php = self.probe_http_endpoint(target_ip, port, path="/index.php", timeout=timeout)
            if probe_php:
                probe_res = probe_php

        if not probe_res:
            return None

        headers = probe_res.get("headers", {})
        body = probe_res.get("body_snippet", "")

        # Look for PHP version in headers
        x_powered = headers.get("x-powered-by", "")
        server_hdr = headers.get("server", "")
        cookie_hdr = headers.get("set-cookie", "")

        version_info = parse_php_version(x_powered)
        detection_source = f"Header 'X-Powered-By: {x_powered}'"

        if not version_info and "php" in server_hdr.lower():
            version_info = parse_php_version(server_hdr)
            detection_source = f"Header 'Server: {server_hdr}'"

        if not version_info and ("php version" in body.lower() or "php/" in body.lower()):
            version_info = parse_php_version(body)
            detection_source = "HTTP response body banner"

        if version_info:
            major, minor, patch, ver_str = version_info
            is_vuln, reason = is_php_version_vulnerable(major, minor, patch)
            return {
                "port": port,
                "php_detected": True,
                "version": ver_str,
                "source": detection_source,
                "is_vulnerable": is_vuln,
                "reason": reason
            }

        # Check if PHP is running but version is concealed (expose_php = Off)
        if "phpsessid" in cookie_hdr.lower() or "php" in server_hdr.lower() or "php" in x_powered.lower():
            return {
                "port": port,
                "php_detected": True,
                "version": "Concealed (expose_php = Off)",
                "source": "Session cookie (PHPSESSID) or server indicator",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "PHP engine detected via session state or headers, but exact version string is hidden "
                    "(expose_php = Off). Manually verify PHP runtime patch level against CVE-2026-109619."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified web ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        safe_findings: List[str] = []
        concealed_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("php_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] PHP {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] PHP {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-109619 (PHP2Shell) confirmed on {target_ip}.\n"
                f"Vulnerable services detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-109619 - CVSS 9.2):\n"
                f"The target host {target_ip} executes a vulnerable PHP core runtime version.\n"
                f"Flaw Overview: PHP core engine fails to reset or repopulates global state pointers pointing "
                f"into request memory across abnormal request terminations. Subsequent worker requests reusing "
                f"the thread/process will access stale, freed memory, enabling remote memory corruption and "
                f"arbitrary code execution (RCE).\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately upgrade PHP to fixed releases: 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+.\n"
                f"2. Retire or backport patches for all EOL PHP branches (5.x, 7.x, 8.0.x, 8.1.x).\n"
                f"3. Restrict administrative endpoints and monitor FastCGI/PHP-FPM worker cycles."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "PHP runtime active with concealed version headers."
            details = (
                f"PHP detected on {target_ip} with concealed version headers (expose_php = Off):\n"
                + "\n".join(concealed_findings) + "\n\n"
                f"Please verify that the underlying PHP package has been updated to fixed versions "
                f"(PHP 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+)."
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: PHP services detected on {target_ip} are running patched versions resistant "
                f"to CVE-2026-109619:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable PHP runtime instances or banners detected on target ports."
        )

