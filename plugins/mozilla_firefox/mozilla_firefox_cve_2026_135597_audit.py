"""
mozilla_firefox_cve_2026_135597_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for Mozilla Firefox,
Firefox ESR, Headless Firefox (Remote Agent / WebDriver BiDi /json/version,
Selenium Grid / GeckoDriver /status, Playwright / Browserless endpoints), and
Mozilla Thunderbird services against the November 2026 Mozilla Security Bulletins
(18 Critical Sandbox Escape CVEs, CVSS 9.6):
  - Fixed in Firefox 161, Firefox ESR 115.46, Firefox ESR 153.8, Thunderbird 161, and Thunderbird 153.8:
    CVE-2026-135547, CVE-2026-135530, CVE-2026-135525, CVE-2026-135521,
    CVE-2026-135520, CVE-2026-135509, CVE-2026-135508.
  - Fixed in Firefox 161, Firefox ESR 153.8, Thunderbird 161, and Thunderbird 153.8:
    CVE-2026-135597, CVE-2026-135596, CVE-2026-135571, CVE-2026-135529,
    CVE-2026-135519, CVE-2026-135506.
  - Fixed in Firefox 161 and Thunderbird 161:
    CVE-2026-135582, CVE-2026-135578, CVE-2026-135513, CVE-2026-135510,
    CVE-2026-135501.

Affected Versions:
  - Mozilla Firefox / Thunderbird mainline prior to 161.0 (Fixed in 161.0+)
  - Mozilla Firefox ESR / Thunderbird 153.x prior to 153.8 (Fixed in 153.8+)
  - Mozilla Firefox ESR 115.x prior to 115.46 (Fixed in 115.46+)

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
                return self.format_result("Skipped", details="Requirements not met (no target Firefox/WebDriver ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_FIREFOX_PORTS = [4444, 9222, 2828, 3000, 8080, 8443, 80, 443]
SSL_PORTS = {443, 8443, 9443}


def parse_firefox_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts a 3-component Mozilla Firefox / Firefox ESR / Thunderbird version tuple
    (major, minor, patch, raw_str) from WebDriver /status, Remote Agent /json/version,
    or HTTP headers.
    Examples:
      - '"Browser": "Firefox/160.0.2"' -> (160, 0, 2, '160.0.2')
      - '"browserName": "firefox", "browserVersion": "153.7.0"' -> (153, 7, 0, '153.7.0')
      - 'Thunderbird/153.6' -> (153, 6, 0, '153.6.0')
    """
    if not text:
        return None

    patterns = [
        r"(?:HeadlessFirefox|Firefox|Thunderbird)[/\s:v]+([0-9]{2,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?(?:esr)?",
        r'"browserName"\s*:\s*"firefox"[^}]{0,200}?"browserVersion"\s*:\s*"([0-9]{2,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?(?:esr)?"',
        r'"browserVersion"\s*:\s*"([0-9]{2,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?(?:esr)?"[^}]{0,200}?"browserName"\s*:\s*"firefox"',
        r'"Browser"\s*:\s*"(?:Mozilla\s+)?(?:Firefox|Thunderbird)/([0-9]{2,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?(?:esr)?"',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            ver_str = f"{major}.{minor}.{patch}"
            return major, minor, patch, ver_str

    return None


def is_firefox_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Mozilla Firefox / Firefox ESR / Thunderbird version tuple
    (major, minor, patch) is affected by the November 2026 Mozilla Security Advisories
    (18 Critical Sandbox Escape CVEs, CVSS 9.6):
      - ESR 115.x: prior to 115.46.0 (< 115.46)
      - ESR 153.x: prior to 153.8.0 (< 153.8)
      - Mainline: prior to 161.0.0 (< 161.0)
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if major == 115:
        if ver_tuple < (115, 46, 0):
            return True, (
                f"Mozilla Firefox ESR {ver_str} is prior to 115.46 and is affected by 7 critical sandbox escape CVEs: "
                f"CVE-2026-135547, CVE-2026-135530, CVE-2026-135525, CVE-2026-135521, CVE-2026-135520, "
                f"CVE-2026-135509, and CVE-2026-135508 (CVSS 9.6)."
            )
        return False, (
            f"Mozilla Firefox ESR {ver_str} is patched (>= 115.46) against CVE-2026-135547..CVE-2026-135508."
        )

    if major == 153:
        if ver_tuple < (153, 8, 0):
            return True, (
                f"Mozilla Firefox ESR / Thunderbird {ver_str} is prior to 153.8 and is affected by 13 critical "
                f"sandbox escape CVEs: CVE-2026-135597, CVE-2026-135596, CVE-2026-135571, CVE-2026-135529, "
                f"CVE-2026-135519, CVE-2026-135506, CVE-2026-135547, CVE-2026-135530, CVE-2026-135525, "
                f"CVE-2026-135521, CVE-2026-135520, CVE-2026-135509, and CVE-2026-135508 (CVSS 9.6)."
            )
        return False, (
            f"Mozilla Firefox ESR / Thunderbird {ver_str} is patched (>= 153.8) against "
            f"CVE-2026-135597..CVE-2026-135508."
        )

    if ver_tuple < (161, 0, 0):
        return True, (
            f"Mozilla Firefox / Thunderbird {ver_str} is prior to 161.0 and is affected by 18 critical sandbox "
            f"escape CVEs: CVE-2026-135597, CVE-2026-135596, CVE-2026-135582, CVE-2026-135578, CVE-2026-135571, "
            f"CVE-2026-135529, CVE-2026-135519, CVE-2026-135513, CVE-2026-135510, CVE-2026-135506, "
            f"CVE-2026-135501, CVE-2026-135547, CVE-2026-135530, CVE-2026-135525, CVE-2026-135521, "
            f"CVE-2026-135520, CVE-2026-135509, and CVE-2026-135508 (CVSS 9.6)."
        )

    return False, (
        f"Mozilla Firefox / Thunderbird {ver_str} is patched (>= 161.0) against "
        f"CVE-2026-135597..CVE-2026-135501."
    )


class MozillaFirefoxAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Mozilla Firefox, Firefox ESR & Thunderbird Sandbox Escape Compliance Audit
    (CVE-2026-135597..CVE-2026-135501 — 18 Critical CVEs).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Mozilla Firefox, Firefox ESR & Thunderbird Sandbox Escape Audit (CVE-2026-135597)",
            "description": (
                "Passive version compliance check for Mozilla Firefox, Firefox ESR, Headless Firefox / GeckoDriver "
                "& Thunderbird endpoints (< 161.0, ESR < 153.8, ESR < 115.46) against 18 critical sandbox escape "
                "CVEs including CVE-2026-135597..CVE-2026-135501 (CVSS 9.6)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-135597",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_FIREFOX_PORTS.copy()
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
                    or "firefox" in s_name
                    or "gecko" in s_name
                    or "selenium" in s_name
                    or "webdriver" in s_name
                    or "thunderbird" in s_name
                    or "ssl" in s_name
                ):
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
        path: str = "/status",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-135597)",
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
            ("/status", "WebDriver / GeckoDriver / Selenium Grid /status endpoint"),
            ("/wd/hub/status", "Selenium Hub /wd/hub/status"),
            ("/json/version", "Firefox Remote Agent / WebDriver BiDi /json/version"),
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
                "firefox" in combined_lower
                or "geckodriver" in combined_lower
                or "thunderbird" in combined_lower
                or "moz:" in combined_lower
            ):
                ver_info = parse_firefox_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_firefox_version_vulnerable(major, minor, patch)
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
                    f"- [{port_label}] Mozilla Firefox / Thunderbird {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Mozilla Firefox / Thunderbird {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-135597..CVE-2026-135501 affected Mozilla Firefox / Thunderbird version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-135597..CVE-2026-135501 - 18 CVEs, CVSS 9.6):\n"
                f"The target host {target_ip} exposes a Mozilla Firefox, Firefox ESR, or Thunderbird runtime prior to the November 2026 security updates.\n\n"
                f"Advisory Summary:\n"
                f"- Fixed in Firefox 161, Firefox ESR 115.46, Firefox ESR 153.8, Thunderbird 161 & 153.8 (CVSS 9.6):\n"
                f"  CVE-2026-135547, CVE-2026-135530, CVE-2026-135525, CVE-2026-135521, CVE-2026-135520, "
                f"CVE-2026-135509, CVE-2026-135508.\n"
                f"- Fixed in Firefox 161, Firefox ESR 153.8, Thunderbird 161 & 153.8 (CVSS 9.6):\n"
                f"  CVE-2026-135597, CVE-2026-135596, CVE-2026-135571, CVE-2026-135529, CVE-2026-135519, "
                f"CVE-2026-135506.\n"
                f"- Fixed in Firefox 161 & Thunderbird 161 (CVSS 9.6):\n"
                f"  CVE-2026-135582, CVE-2026-135578, CVE-2026-135513, CVE-2026-135510, CVE-2026-135501.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Update Mozilla Firefox / Thunderbird to >= 161.0, Firefox ESR / Thunderbird 153.x to >= 153.8, or Firefox ESR 115.x to >= 115.46.\n"
                f"2. Restrict network access to WebDriver / GeckoDriver and Firefox Remote Agent ports."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Mozilla Firefox / Thunderbird instance on {target_ip} meets the minimum patched release (>= 161.0 / ESR >= 153.8 / ESR >= 115.46):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Mozilla Firefox / Thunderbird services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Mozilla Firefox / Firefox ESR & Thunderbird (CVE-2026-135597..CVE-2026-135501)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_FIREFOX_PORTS,
        help="Ports to inspect (default: 4444 9222 2828 3000 8080 8443 80 443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = MozillaFirefoxAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Mozilla Firefox / Thunderbird version affected by CVE-2026-135597.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
