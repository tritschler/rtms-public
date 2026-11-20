"""
jetbrains_teamcity_cve_2026_132234_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS login page and REST metadata version verification
for JetBrains TeamCity Server against the November 2026 Security Advisories (5 CVEs):
  - CVE-2026-132234 (CVSS 9.9 Critical): Remote Code Execution via argument injection in Mercurial VCS root settings.
  - CVE-2026-132233 (CVSS 9.9 Critical): Remote Code Execution via build attribute injection.
  - CVE-2026-132232 (CVSS 9.9 Critical): Remote Code Execution via argument injection in Perforce settings.
  - CVE-2026-132231 (CVSS 9.9 Critical): Remote Code Execution via best-fit character mapping in Perforce settings.
  - CVE-2026-132891 (CVSS 9.8 Critical): Remote Code Execution via external pull requests (< 2025.11.8, 2026.1.x < 2026.1.4).

Affected Versions:
  - JetBrains TeamCity: all versions < 2025.11.8, and 2026.1.x prior to 2026.1.4 (2026.1.0 - 2026.1.3)

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
                return self.format_result("Skipped", details="Requirements not met (no target TeamCity ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_TEAMCITY_PORTS = [8111, 80, 443, 8080, 8443]
SSL_PORTS = {443, 8443}


def parse_teamcity_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts JetBrains TeamCity version tuple (year, minor, patch, raw_str)
    from TeamCity login page footer, headers, or REST server metadata.

    Examples:
      - 'TeamCity Enterprise 2026.1.2 (build 197550)' -> (2026, 1, 2, '2026.1.2')
      - '<span class="vWord">Version</span> 2025.11.5' -> (2025, 11, 5, '2025.11.5')
      - 'TeamCity Professional 2026.1 (build 197500)' -> (2026, 1, 0, '2026.1.0')
    """
    if not text:
        return None

    patterns = [
        r"TeamCity(?:\s+(?:Enterprise|Professional|Server|Version))?[\s:/v-]+(20[12][0-9])\.([0-9]{1,2})(?:\.([0-9]{1,2}))?\b",
        r'(?:class="vWord">\s*Version\s*</span>|"version"\s*:\s*"|version=")\s*(20[12][0-9])\.([0-9]{1,2})(?:\.([0-9]{1,2}))?\b',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            year = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            raw_str = f"{year}.{minor}.{patch}" if match.group(3) is not None else f"{year}.{minor}"
            return year, minor, patch, raw_str

    return None


def is_teamcity_version_vulnerable(
    year: int,
    minor: int,
    patch: int,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether a JetBrains TeamCity version is affected by:
      - CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231 (CVSS 9.9): < 2025.11.7, 2026.1.0..2026.1.2
      - CVE-2026-132891 (CVSS 9.8): < 2025.11.8, 2026.1.0..2026.1.3
    """
    ver = (year, minor, patch)
    ver_display = raw_str or f"{year}.{minor}.{patch}"

    if ver < (2025, 11, 7):
        return True, (
            f"JetBrains TeamCity {ver_display} is prior to 2025.11.7 and is affected by "
            f"CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231 (CVSS 9.9), "
            f"and CVE-2026-132891 (CVSS 9.8)."
        )

    if ver == (2025, 11, 7):
        return True, (
            f"JetBrains TeamCity {ver_display} is prior to 2025.11.8 and is affected by "
            f"CVE-2026-132891 (CVSS 9.8)."
        )

    if (2025, 11, 8) <= ver < (2026, 1, 0):
        return False, (
            f"JetBrains TeamCity {ver_display} is patched in the 2025.11.x branch (>= 2025.11.8) against "
            f"CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231, and CVE-2026-132891."
        )

    if (2026, 1, 0) <= ver < (2026, 1, 3):
        return True, (
            f"JetBrains TeamCity {ver_display} is prior to 2026.1.3 and is affected by "
            f"CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231 (CVSS 9.9), "
            f"and CVE-2026-132891 (CVSS 9.8)."
        )

    if ver == (2026, 1, 3):
        return True, (
            f"JetBrains TeamCity {ver_display} is prior to 2026.1.4 and is affected by "
            f"CVE-2026-132891 (CVSS 9.8)."
        )

    return False, (
        f"JetBrains TeamCity {ver_display} is patched (>= 2026.1.4) against "
        f"CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231, and CVE-2026-132891."
    )


class JetBrainsTeamCityAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: JetBrains TeamCity Version Compliance Audit
    (CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231, CVE-2026-132891).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "JetBrains TeamCity Version Compliance Audit (CVE-2026-132234 / CVE-2026-132891)",
            "description": (
                "Passive version compliance check for JetBrains TeamCity (< 2025.11.8 and 2026.1.x < 2026.1.4) "
                "against CVE-2026-132234, CVE-2026-132233, CVE-2026-132232, CVE-2026-132231 (CVSS 9.9), "
                "and CVE-2026-132891 (CVSS 9.8)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-132234",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_TEAMCITY_PORTS.copy()
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

                if port in self.target_ports or "teamcity" in s_name or "http" in s_name:
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
        path: str = "/login.html",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-132234)",
                "Accept": "text/html,application/xhtml+xml,application/json,application/xml,*/*",
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
            logger.debug(f"TeamCity HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/login.html", "TeamCity Web Login Page"),
            ("/app/rest/server", "TeamCity REST Server Endpoint"),
            ("/", "HTTP Root Banner / Headers"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            if "teamcity" in combined.lower() or "tc-csrf-token" in combined.lower():
                ver_info = parse_teamcity_version(combined)
                if ver_info:
                    year, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_teamcity_version_vulnerable(year, minor, patch, ver_str)
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
                    f"- [{port_label}] JetBrains TeamCity {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] JetBrains TeamCity {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-132231..CVE-2026-132234 / CVE-2026-132891 affected JetBrains TeamCity detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-132234, CVE-2026-132891 & Related Advisories - CVSS 9.8–9.9):\n"
                f"The target host {target_ip} exposes an unpatched JetBrains TeamCity instance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-132234 (CVSS 9.9): Remote code execution via argument injection in Mercurial VCS root settings.\n"
                f"- CVE-2026-132233 (CVSS 9.9): Remote code execution via build attribute injection.\n"
                f"- CVE-2026-132232 (CVSS 9.9): Remote code execution via argument injection in Perforce settings.\n"
                f"- CVE-2026-132231 (CVSS 9.9): Remote code execution via best-fit character mapping in Perforce settings.\n"
                f"- CVE-2026-132891 (CVSS 9.8): Remote code execution via external pull requests.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade JetBrains TeamCity to version 2026.2+, 2026.1.4+, or 2025.11.8+.\n"
                f"2. Restrict network access to the TeamCity web interface and VCS administration endpoints."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: JetBrains TeamCity instance on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected JetBrains TeamCity services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for JetBrains TeamCity (CVE-2026-132231..CVE-2026-132234)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_TEAMCITY_PORTS,
        help="Ports to inspect (default: 8111 80 443 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = JetBrainsTeamCityAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a JetBrains TeamCity version affected by CVE-2026-132234.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
