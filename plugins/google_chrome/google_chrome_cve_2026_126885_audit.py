"""
google_chrome_cve_2026_126885_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for Google Chrome / Headless Chromium
services (Chrome DevTools Protocol /json/version, Selenium Grid / WebDriver /status, Browserless,
and rendering services) against the November 2026 Chrome Security Bulletin:
  - CVE-2026-126885 (CVSS 9.6 Critical): Use-after-free in ServiceWorker in Google Chrome (< 157.0.8103.78).
  - CVE-2026-126846 (CVSS 9.6 Critical): Use-after-free in Skia in Google Chrome (< 157.0.8103.78).
  - CVE-2026-126872 (CVSS 9.6 Critical): Incorrect authorization in FileSystem in Google Chrome (< 157.0.8103.78).
  - CVE-2026-126842 (CVSS 9.6 Critical): Use-after-free in ANGLE in Google Chrome (< 157.0.8103.78).
  - CVE-2026-126909 (CVSS 9.6 Critical): Use-after-free in Passwords in Google Chrome (< 157.0.8103.78).
  - CVE-2026-126912 (CVSS 9.6 Critical): Buffer overflow in Skia in Google Chrome (< 157.0.8103.78).
  - CVE-2026-126859 (CVSS 9.6 Critical): Link following in FileSystem in Google Chrome (< 157.0.8103.78).

Affected Versions:
  - Google Chrome / Chromium prior to 157.0.8103.78 (Fixed in 157.0.8103.78+)

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
                return self.format_result("Skipped", details="Requirements not met (no target Chrome/CDP ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_CHROME_PORTS = [9222, 9229, 9515, 4444, 3000, 8080, 8443, 80, 443]
SSL_PORTS = {443, 8443, 9443}
MIN_PATCHED_CHROME = (157, 0, 8103, 78)


def parse_chrome_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts 4-component Google Chrome / HeadlessChrome / Chromium version tuple
    (major, minor, build, patch, raw_str) from CDP /json/version, WebDriver /status,
    or HTTP headers.
    Examples:
      - '"Browser": "HeadlessChrome/157.0.8103.50"' -> (157, 0, 8103, 50, '157.0.8103.50')
      - '"browserVersion": "157.0.8103.78"' -> (157, 0, 8103, 78, '157.0.8103.78')
      - 'Chrome/156.0.7990.120' -> (156, 0, 7990, 120, '156.0.7990.120')
    """
    if not text:
        return None

    patterns = [
        r"(?:HeadlessChrome|Chrome|Chromium)[/\s:v]+([0-9]{2,3})\.([0-9]+)\.([0-9]{3,5})\.([0-9]{1,4})",
        r'"(?:Browser|browserVersion|chromeVersion)"\s*:\s*"(?:[A-Za-z]+/)?([0-9]{2,3})\.([0-9]+)\.([0-9]{3,5})\.([0-9]{1,4})"',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            build = int(match.group(3))
            patch = int(match.group(4))
            ver_str = f"{major}.{minor}.{build}.{patch}"
            return major, minor, build, patch, ver_str

    return None


def is_chrome_version_vulnerable(major: int, minor: int, build: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Google Chrome / Chromium version tuple is prior to 157.0.8103.78
    and affected by CVE-2026-126885, CVE-2026-126846, CVE-2026-126872, CVE-2026-126842,
    CVE-2026-126909, CVE-2026-126912, and CVE-2026-126859 (CVSS 9.6).
    """
    ver_tuple = (major, minor, build, patch)
    ver_str = f"{major}.{minor}.{build}.{patch}"

    if ver_tuple < MIN_PATCHED_CHROME:
        return True, (
            f"Google Chrome / Chromium {ver_str} is prior to 157.0.8103.78 and is affected by "
            f"CVE-2026-126885, CVE-2026-126846, CVE-2026-126872, CVE-2026-126842, "
            f"CVE-2026-126909, CVE-2026-126912, and CVE-2026-126859 (CVSS 9.6 Sandbox Escape / Memory Corruption)."
        )

    return False, (
        f"Google Chrome / Chromium {ver_str} is patched (>= 157.0.8103.78) against "
        f"CVE-2026-126885..CVE-2026-126912."
    )


class GoogleChromeAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Google Chrome / Chromium Headless & CDP Endpoint Compliance Audit
    (CVE-2026-126885, CVE-2026-126846, CVE-2026-126872, CVE-2026-126842,
    CVE-2026-126909, CVE-2026-126912, CVE-2026-126859).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Google Chrome & Headless Chromium Sandbox Escape Audit (CVE-2026-126885)",
            "description": (
                "Passive version compliance check for Google Chrome / Chromium CDP & WebDriver endpoints "
                "(< 157.0.8103.78) against CVE-2026-126885, CVE-2026-126846, CVE-2026-126872, "
                "CVE-2026-126842, CVE-2026-126909, CVE-2026-126912, and CVE-2026-126859 (CVSS 9.6)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-126885",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_CHROME_PORTS.copy()
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
                    or "chrome" in s_name
                    or "devtools" in s_name
                    or "selenium" in s_name
                    or "webdriver" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 4444, 8080, 8443, 9222, 9515):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/json/version",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-126885)",
                "Accept": "application/json,text/html,*/*",
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
            ("/json/version", "Chrome DevTools Protocol /json/version"),
            ("/status", "WebDriver / Selenium Grid /status endpoint"),
            ("/wd/hub/status", "Selenium Hub /wd/hub/status"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"
            combined_lower = combined.lower()

            if (
                "headlesschrome" in combined_lower
                or "chromium" in combined_lower
                or "chrome/" in combined_lower
                or "webkit-version" in combined_lower
                or "webdebuggerurl" in combined_lower
                or "chromedriver" in combined_lower
            ):
                ver_info = parse_chrome_version(combined)
                if ver_info:
                    major, minor, build, patch, ver_str = ver_info
                    is_vuln, reason = is_chrome_version_vulnerable(major, minor, build, patch)
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
                    f"- [{port_label}] Google Chrome / Chromium {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Google Chrome / Chromium {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-126885..CVE-2026-126912 affected Google Chrome / Chromium version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-126885 & Related Advisories - CVSS 9.6):\n"
                f"The target host {target_ip} exposes a Google Chrome / Headless Chromium instance prior to 157.0.8103.78.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-126885, CVE-2026-126846, CVE-2026-126872, CVE-2026-126842, CVE-2026-126909, "
                f"CVE-2026-126912, CVE-2026-126859 (CVSS 9.6): Multiple Use-After-Free, Buffer Overflow, "
                f"and Incorrect Authorization flaws in ServiceWorker, Skia, ANGLE, FileSystem, and Passwords "
                f"enabling sandbox escape.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Update Google Chrome / Chromium packages and container images to >= 157.0.8103.78.\n"
                f"2. Bind Chrome DevTools Protocol (--remote-debugging-port) to 127.0.0.1 and restrict external network access."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Google Chrome / Chromium instance on {target_ip} meets the minimum patched release (>= 157.0.8103.78):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Google Chrome / Headless Chromium services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Google Chrome / Headless Chromium (CVE-2026-126885..CVE-2026-126912)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_CHROME_PORTS,
        help="Ports to inspect (default: 9222 9229 9515 4444 3000 8080 8443 80 443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = GoogleChromeAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Google Chrome / Chromium version affected by CVE-2026-126885.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
