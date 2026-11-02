"""
pgadmin4_cve_2026_116241_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 80, 443, 5050, 5051, 8080, 8443, 8888) for
pgAdmin 4 Server Mode deployments (versions < 9.19) vulnerable to:
  - CVE-2026-116241 (CVSS 9.4 Critical): psql \\copy (...) TO PROGRAM Wrapper Escape RCE
    in the Import/Export Data tool (bypass of CVE-2026-17566).
  - CVE-2026-116238 (CVSS 9.2 Critical): Flask-Security /login & Account Lockout
    (MAX_LOGIN_ATTEMPTS) Authentication Bypass.

CVSS Score: 9.4 (Critical) - CWE-78 (OS Command Injection) / CWE-287 (Improper Authentication)
Affected Components: pgAdmin 4 Server Mode (all versions < 9.19).
Fixed in: pgAdmin 4 9.19+.

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
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/pgAdmin ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Common ports serving pgAdmin 4 (5050 is the default standalone/Docker port)
DEFAULT_PGADMIN_PORTS = [80, 443, 5050, 5051, 8080, 8443, 8888, 9443]
SSL_PORTS = {443, 5051, 8443, 9443, 4433, 10443}

# Patched threshold: pgAdmin 4 9.19+ fixes both CVE-2026-116241 and CVE-2026-116238 (< 9.19 is vulnerable)
MIN_PATCHED_VERSION = (9, 19, 0)


def parse_pgadmin4_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts pgAdmin 4 semantic version (major, minor, patch, raw_str) from:
      1. pgAdmin 4 integer asset query parameter: ?ver=91800 -> (9, 18, 0, '9.18') or ?ver=81401 -> (8, 14, 1, '8.14.1')
      2. Dotted asset query parameter: ?ver=9.18 or ?ver=9.18.0
      3. HTML / JS version strings: 'pgAdmin 4 v9.18', 'version: "9.18"', '"app_version": "9.18"'
    """
    if not text:
        return None

    # 1. Check pgAdmin's 5-digit integer ?ver=MNNPP asset version scheme (e.g. ?ver=91800 -> 9.18.0)
    int_ver_match = re.search(r"\?ver=([1-9][0-9]{4})\b", text)
    if int_ver_match:
        ver_int = int(int_ver_match.group(1))
        major = ver_int // 10000
        minor = (ver_int % 10000) // 100
        patch = ver_int % 100
        raw_ver = f"{major}.{minor}" if patch == 0 else f"{major}.{minor}.{patch}"
        return major, minor, patch, raw_ver

    # 2. Check dotted version patterns
    patterns = [
        r"\?ver=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"pgAdmin\s*4\s*v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"(?:app_version|version_name|APP_VERSION)['\"\s:=]+v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"^v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            raw_ver = f"{major}.{minor}" if match.group(3) is None else f"{major}.{minor}.{patch}"
            return major, minor, patch, raw_ver

    return None


def is_pgadmin4_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates pgAdmin 4 version tuple against CVE-2026-116241 & CVE-2026-116238 (< 9.19 is vulnerable).
    Returns (is_vulnerable, explanation).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}" if patch == 0 else f"{major}.{minor}.{patch}"

    if ver_tuple < MIN_PATCHED_VERSION:
        return True, (
            f"pgAdmin 4 {ver_str} is vulnerable to CVE-2026-116241 (CVSS 9.4 RCE via psql \\copy wrapper escape) "
            f"and CVE-2026-116238 (CVSS 9.2 Flask-Security /login lockout bypass). "
            f"Affected: < 9.19; requires upgrade to >= 9.19."
        )

    return False, (
        f"pgAdmin 4 {ver_str} is patched against CVE-2026-116241 and CVE-2026-116238 "
        f"(running >= 9.19)."
    )


class PgAdmin4SecurityAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: pgAdmin 4 psql \\copy RCE & Lockout Bypass Audit (CVE-2026-116241 / CVE-2026-116238).
    Performs safe, non-destructive HTTP/HTTPS fingerprinting of pgAdmin 4 Server Mode endpoints.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "pgAdmin 4 psql copy RCE & Lockout Bypass Audit (CVE-2026-116241)",
            "description": "Audits HTTP/HTTPS endpoints (ports 80, 443, 5050, 8080, 8443) for pgAdmin 4 Server Mode (< 9.19) vulnerable to psql \\copy TO PROGRAM RCE (CVE-2026-116241) and Flask-Security account lockout bypass (CVE-2026-116238).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-116241",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_PGADMIN_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers web, HTTP, HTTPS, or pgAdmin ports on the target host.
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
                    or "web" in s_name
                    or "pgadmin" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 5050, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/login",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Safely performs a read-only HTTP/HTTPS GET request to inspect pgAdmin 4 headers and login HTML.
        """
        use_ssl = port in SSL_PORTS or port in (443, 5051, 8443, 9443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-116241)",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
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
        Probes standard pgAdmin 4 paths (/login, /pgadmin4/login, /) to detect pgAdmin 4 and extract its version.
        """
        candidate_paths = ["/login", "/pgadmin4/login", "/"]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            cookie_hdr = headers.get("set-cookie", "").lower()
            location_hdr = headers.get("location", "").lower()
            body_lower = body.lower()

            is_pgadmin = (
                "pga4_session" in cookie_hdr
                or "pgadmin4" in cookie_hdr
                or "pgadmin 4" in body_lower
                or "pgadmin4" in body_lower
                or "pgadmin.login" in body_lower
                or "/pgadmin4/login" in location_hdr
            )

            if not is_pgadmin:
                continue

            ver_info = parse_pgadmin4_version(body)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_pgadmin4_version_vulnerable(major, minor, patch)
                return {
                    "port": port,
                    "pgadmin_detected": True,
                    "version": ver_str,
                    "source": f"HTTP GET {path} (asset/page version metadata)",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            # If root redirected to /login or /pgadmin4/login without body version, continue to next path
            if path == "/" and probe.get("status_code") in (301, 302, 303, 307, 308):
                continue

            return {
                "port": port,
                "pgadmin_detected": True,
                "version": "Concealed (version metadata hidden)",
                "source": f"HTTP GET {path} (pga4_session cookie / pgAdmin 4 login page)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"pgAdmin 4 Server Mode detected on port {port} ({path}), but exact version "
                    f"metadata is concealed. Manually verify in Help > About pgAdmin 4 that the "
                    f"deployment runs version 9.19 or newer."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified web/pgAdmin ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("pgadmin_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] pgAdmin 4 v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] pgAdmin 4 v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-116241 & CVE-2026-116238 confirmed on {target_ip}.\n"
                f"Vulnerable pgAdmin 4 Server Mode instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-116241 CVSS 9.4 / CVE-2026-116238 CVSS 9.2):\n"
                f"The target host {target_ip} runs a vulnerable pgAdmin 4 Server Mode version (< 9.19).\n"
                f"Flaw Overview:\n"
                f"1. CVE-2026-116241 (CVSS 9.4 - RCE): pgAdmin 4's Import/Export Data tool wraps query exports "
                f"in a psql \\copy (...) TO command and checks parenthesis balance, but fails to reject backslashes "
                f"inside double-quoted identifiers. With standard_conforming_strings=off, an attacker can escape "
                f"the wrapper and append a 'TO PROGRAM' clause executed as the OS user running pgAdmin 4.\n"
                f"2. CVE-2026-116238 (CVSS 9.2 - Auth Bypass): Unauthenticated attackers can bypass "
                f"MAX_LOGIN_ATTEMPTS account lockout by submitting credentials to Flask-Security's raw /login "
                f"view or varying username casing, allowing unlimited brute-force attacks against the admin account.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately upgrade pgAdmin 4 to version 9.19 or later.\n"
                f"2. Restrict network access to pgAdmin 4 behind a VPN or reverse proxy with MFA.\n"
                f"3. Block external access to Flask-Security fallback routes (/verify, /change, /reset) if unpatched."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "pgAdmin 4 Server Mode active with concealed version metadata."
            details = (
                f"pgAdmin 4 Server Mode detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: pgAdmin 4 instances on {target_ip} are running patched versions (>= 9.19) "
                f"resistant to CVE-2026-116241 and CVE-2026-116238:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable pgAdmin 4 Server Mode instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for pgAdmin 4 RCE & Lockout Bypass vulnerabilities (CVE-2026-116241 / CVE-2026-116238)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 5050, 8080, 8443],
        help="Ports to inspect (default: 80 443 5050 8080 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-116241 Auditor (pgAdmin 4)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = PgAdmin4SecurityAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-116241 / CVE-2026-116238!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual patch verification.\n")
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
