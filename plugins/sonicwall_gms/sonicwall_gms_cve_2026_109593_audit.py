"""
sonicwall_gms_cve_2026_109593_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 80, 443, 8080, 8443) for SonicWall Global Management System (GMS)
instances (versions <= 9.5.2) vulnerable to CVE-2026-109593 (Unauthenticated Arbitrary Internal File Read
& Sensitive Information Disclosure).

CVSS Score: 9.1 (Critical) - CWE-22 / CWE-200 (Arbitrary File Read / Sensitive Information Exposure)
Affected Components: SonicWall Global Management System (GMS) versions <= 9.5.2.
Fixed in: SonicWall GMS > 9.5.2 (9.5.3+).

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
                return self.format_result("Skipped", details="Requirements not met (no target SonicWall GMS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard SonicWall Global Management System (GMS) web management ports
DEFAULT_SONICWALL_GMS_PORTS = [80, 443, 8080, 8443]
SSL_PORTS = {443, 8443}
MAX_VULNERABLE_VERSION = (9, 5, 2)


def parse_sonicwall_gms_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts SonicWall GMS version (major, minor, patch, raw_str) from:
      1. Login page HTML / title / footer: SonicWall Global Management System 9.5.2, GMS 9.5.1, Version 9.5.2
      2. Static asset query strings in /sgms/ pages: ?v=9.5.2 or ?ver=9.5.2
      3. JSON or metadata attributes: "version": "9.5.2"
    """
    if not text:
        return None

    patterns = [
        r'(?:Global\s+Management\s+System|SonicWall\s+GMS|SGMS|GMS|Version)[^0-9\r\n]{1,25}v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[\.\-][0-9a-zA-Z]+)?\b',
        r'\?(?:v|ver|version)=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',
        r'"version"\s*:\s*"v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?"',
        r'^v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch_raw = match.group(3)
            patch = int(patch_raw) if patch_raw is not None else 0
            raw_str = f"{major}.{minor}.{patch_raw}" if patch_raw is not None else f"{major}.{minor}"
            return major, minor, patch, raw_str

    return None


def is_sonicwall_gms_vulnerable(major: int, minor: int, patch: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates SonicWall GMS version against CVE-2026-109593 (<= 9.5.2 is vulnerable).
    """
    ver_tuple = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if ver_tuple <= MAX_VULNERABLE_VERSION:
        return True, (
            f"SonicWall Global Management System (GMS) {ver_display} is vulnerable to CVE-2026-109593 "
            f"(CVSS 9.1 unauthenticated arbitrary internal file read; affected: <= 9.5.2, requires > 9.5.2)."
        )

    return False, (
        f"SonicWall Global Management System (GMS) {ver_display} is patched against CVE-2026-109593 "
        f"(running > 9.5.2)."
    )


class SonicWallGmsAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: SonicWall GMS Unauthenticated File Read Audit (CVE-2026-109593).
    Performs safe, non-destructive HTTP/HTTPS fingerprinting of SonicWall GMS management consoles.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "SonicWall GMS Unauthenticated Internal File Read Audit (CVE-2026-109593)",
            "description": "Audits HTTP/HTTPS endpoints (ports 80, 443, 8080, 8443) for SonicWall Global Management System (GMS <= 9.5.2) vulnerable to unauthenticated arbitrary internal file read (CVE-2026-109593).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-109593",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_SONICWALL_GMS_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or SonicWall GMS management ports on the target host.
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
                    or "sonicwall" in s_name
                    or "sgms" in s_name
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
        path: str = "/sgms/login",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect SonicWall GMS headers and login HTML.
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-109593)",
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
        Probes standard SonicWall GMS paths (/sgms/login, /appliance/login, /) to detect the appliance and version.
        """
        candidate_paths = ["/sgms/login", "/appliance/login", "/"]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            cookie_hdr = headers.get("set-cookie", "").lower()
            location_hdr = headers.get("location", "").lower()
            server_hdr = headers.get("server", "").lower()
            body_lower = body.lower()

            is_sonicwall_gms = (
                "sonicwall global management system" in body_lower
                or "sonicwall universal management" in body_lower
                or ("sonicwall" in body_lower and ("/sgms/" in body_lower or "global management system" in body_lower or "gms" in body_lower))
                or "/sgms/login" in location_hdr
                or "/sgms/auth" in location_hdr
                or ("path=/sgms" in cookie_hdr and "sonicwall" in body_lower)
                or "sonicwall gms" in server_hdr
            )

            if not is_sonicwall_gms:
                continue

            ver_info = parse_sonicwall_gms_version(body)
            if ver_info:
                major, minor, patch, raw_str = ver_info
                is_vuln, reason = is_sonicwall_gms_vulnerable(major, minor, patch, raw_str)
                return {
                    "port": port,
                    "gms_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            if path == "/" and probe.get("status_code") in (301, 302, 303, 307, 308):
                continue

            return {
                "port": port,
                "gms_detected": True,
                "version": "Concealed (GMS version hidden)",
                "source": f"HTTP GET {path} (SonicWall GMS interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"SonicWall Global Management System (GMS) detected on port {port} ({path}), but exact "
                    f"version is concealed. Verify in the System / Appliance console that GMS is updated beyond 9.5.2."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified SonicWall GMS ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("gms_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] SonicWall GMS v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] SonicWall GMS v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-109593 confirmed on {target_ip}.\n"
                f"Vulnerable SonicWall Global Management System (GMS) instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-109593 - CVSS 9.1):\n"
                f"The target host {target_ip} runs a vulnerable SonicWall Global Management System (GMS <= 9.5.2).\n"
                f"Flaw Overview:\n"
                f"An unauthenticated attacker with network access to SonicWall GMS 9.5.2 and earlier versions "
                f"can read arbitrary internal GMS files, exposing sensitive configuration data, credentials, "
                f"and system tokens.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately apply the official SonicWall GMS security update / hotfix (> 9.5.2).\n"
                f"2. Restrict network access to SonicWall GMS web management interfaces (/sgms/, ports 80/443/8080/8443) to trusted management subnets."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "SonicWall Global Management System (GMS) active with concealed version."
            details = (
                f"SonicWall Global Management System (GMS) detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: SonicWall Global Management System (GMS) instances on {target_ip} are running patched versions "
                f"(> 9.5.2) resistant to CVE-2026-109593:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable SonicWall Global Management System (GMS) instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for SonicWall GMS CVE-2026-109593."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 8080, 8443],
        help="Ports to inspect (default: 80 443 8080 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-109593 Auditor (SonicWall GMS)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = SonicWallGmsAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-109593!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual GMS version verification.\n")
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
