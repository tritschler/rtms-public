"""
barracuda_esg_cve_2026_116606_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 80, 443, 8000, 8443) for Barracuda Email Security Gateway (ESG)
appliances (versions < 9.4.0.030) vulnerable to CVE-2026-116606 (Unauthenticated Configuration-Import
Authentication Bypass).

CVSS Score: 9.3 (Critical) - CWE-287 / CWE-306 (Authentication Bypass)
Affected Components: Barracuda Email Security Gateway (ESG) versions < 9.4.0.030.
Fixed in: Barracuda ESG 9.4.0.030+.

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
                return self.format_result("Skipped", details="Requirements not met (no target Barracuda ESG ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard Barracuda Email Security Gateway management ports
DEFAULT_BARRACUDA_PORTS = [80, 443, 8000, 8443]
SSL_PORTS = {443, 8443}
MIN_PATCHED_VERSION = (9, 4, 0, 30)


def parse_barracuda_esg_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts Barracuda ESG 3- or 4-part firmware version (major, minor, maint, build, raw_str) from:
      1. Static asset query strings: /barracuda.css?v=9.4.0.025 or /js/bui.js?v=9.3.1.004
      2. Login page HTML / footer: Firmware v9.4.0.025, Version 9.4.0.030
      3. Header or JSON version string: "9.4.0.025"
    """
    if not text:
        return None

    patterns = [
        r'\?v=([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',
        r'(?:Firmware|Version|Barracuda\s+Email\s+Security\s+Gateway|ESG)[^0-9\r\n]{1,25}v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',
        r'"version"\s*:\s*"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?"',
        r'^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            maint = int(match.group(3))
            build_raw = match.group(4)
            build = int(build_raw) if build_raw is not None else 0
            raw_str = f"{major}.{minor}.{maint}.{build_raw}" if build_raw is not None else f"{major}.{minor}.{maint}"
            return major, minor, maint, build, raw_str

    return None


def is_barracuda_esg_vulnerable(major: int, minor: int, maint: int, build: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates Barracuda ESG firmware version against CVE-2026-116606 (< 9.4.0.030 is vulnerable).
    """
    ver_tuple = (major, minor, maint, build)
    ver_display = raw_str or f"{major}.{minor}.{maint}.{build:03d}"

    if ver_tuple < MIN_PATCHED_VERSION:
        return True, (
            f"Barracuda Email Security Gateway firmware {ver_display} is vulnerable to CVE-2026-116606 "
            f"(CVSS 9.3 unauthenticated configuration-import bypass; affected: < 9.4.0.030, requires >= 9.4.0.030)."
        )

    return False, (
        f"Barracuda Email Security Gateway firmware {ver_display} is patched against CVE-2026-116606 "
        f"(running >= 9.4.0.030)."
    )


class BarracudaEsgAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Barracuda Email Security Gateway Auth Bypass Audit (CVE-2026-116606).
    Performs safe, non-destructive HTTP/HTTPS fingerprinting of Barracuda ESG appliances.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Barracuda Email Security Gateway Auth Bypass Audit (CVE-2026-116606)",
            "description": "Audits HTTP/HTTPS endpoints (ports 80, 443, 8000, 8443) for Barracuda Email Security Gateway appliances (< 9.4.0.030) vulnerable to unauthenticated configuration-import bypass (CVE-2026-116606).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-116606",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_BARRACUDA_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or Barracuda ESG management ports on the target host.
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

                if (
                    port in self.target_ports
                    or "http" in s_name
                    or "barracuda" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
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
        path: str = "/cgi-mod/index.cgi",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect Barracuda ESG headers and login HTML.
        """
        use_ssl = port in SSL_PORTS or port in (443, 8443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-116606)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Connection": "close"
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
                "body_snippet": raw_body[:16384]
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
        Probes standard Barracuda ESG paths (/cgi-mod/index.cgi, /) to detect the appliance and firmware version.
        """
        candidate_paths = ["/cgi-mod/index.cgi", "/"]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            cookie_hdr = headers.get("set-cookie", "").lower()
            location_hdr = headers.get("location", "").lower()
            body_lower = body.lower()

            is_barracuda = (
                "barracuda email security gateway" in body_lower
                or "barracuda spam" in body_lower
                or "barra_counter_session" in cookie_hdr
                or "/cgi-mod/index.cgi" in location_hdr
                or ("barracuda" in body_lower and "/cgi-mod/" in body_lower)
            )

            if not is_barracuda:
                continue

            ver_info = parse_barracuda_esg_version(body)
            if ver_info:
                major, minor, maint, build, raw_str = ver_info
                is_vuln, reason = is_barracuda_esg_vulnerable(major, minor, maint, build, raw_str)
                return {
                    "port": port,
                    "barracuda_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            if path == "/" and probe.get("status_code") in (301, 302, 303, 307, 308):
                continue

            return {
                "port": port,
                "barracuda_detected": True,
                "version": "Concealed (firmware version hidden)",
                "source": f"HTTP GET {path} (Barracuda ESG interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"Barracuda Email Security Gateway detected on port {port} ({path}), but exact "
                    f"firmware version is concealed. Verify in BASIC > Administration that firmware is >= 9.4.0.030."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified Barracuda ESG ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("barracuda_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Barracuda ESG v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] Barracuda ESG v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-116606 confirmed on {target_ip}.\n"
                f"Vulnerable Barracuda Email Security Gateway appliances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-116606 - CVSS 9.3):\n"
                f"The target host {target_ip} runs a vulnerable Barracuda Email Security Gateway firmware (< 9.4.0.030).\n"
                f"Flaw Overview:\n"
                f"An authentication bypass in Barracuda Email Security Gateway versions earlier than 9.4.0.030 "
                f"allows an unauthenticated remote attacker to invoke the configuration-import function and "
                f"restore a crafted backup archive, resulting in unauthorized modification of the appliance's "
                f"global configuration.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately upgrade Barracuda Email Security Gateway firmware to version 9.4.0.030 or later.\n"
                f"2. Restrict access to the web management interface (/cgi-mod/, ports 8000/443) to administrative IPs."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Barracuda Email Security Gateway active with concealed firmware version."
            details = (
                f"Barracuda Email Security Gateway detected on {target_ip} with concealed firmware metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Barracuda Email Security Gateway instances on {target_ip} are running patched firmware "
                f"(>= 9.4.0.030) resistant to CVE-2026-116606:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable Barracuda Email Security Gateway instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for Barracuda Email Security Gateway CVE-2026-116606."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 8000, 8443],
        help="Ports to inspect (default: 80 443 8000 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-116606 Auditor (Barracuda ESG)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = BarracudaEsgAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-116606!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual firmware verification.\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(0)
    elif status == "OK":
        print(f"✅ [SAFE] {args.target} passed audit.")
        print(f"   {result.get('details', '')}\n")
        sys.exit(0)
    else:
        print(f"ℹ️  [{status}] {result.get('details', '')}\n")
        sys.exit(0)
