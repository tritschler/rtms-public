"""
nexus_cve_2026_113373_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 8081, 80, 443, 8443) for Sonatype Nexus
Repository 3 instances (versions 3.86.0 through 3.97.1) vulnerable to
CVE-2026-113373 (Disabled/Locked Account Status Bypass via SAML / OIDC SSO).

CVSS Score: 9.1 (Critical) - CWE-287 / CWE-305 (Authentication Bypass by Primary Weakness)
Affected Components: Sonatype Nexus Repository 3 Pro versions >= 3.86.0 and < 3.98.0.
Fixed in: Sonatype Nexus Repository 3.98.0+.

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
                return self.format_result("Skipped", details="Requirements not met (no target Nexus Repository ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard Sonatype Nexus Repository 3 ports
DEFAULT_NEXUS_PORTS = [8081, 80, 443, 8443]
SSL_PORTS = {443, 8443}
MIN_VULNERABLE_VERSION = (3, 86, 0)
FIXED_VERSION = (3, 98, 0)


def parse_nexus_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Sonatype Nexus Repository version (major, minor, patch, raw_str) from:
      1. Server header: Nexus/3.90.1-01 (PRO) or Nexus/3.95.0-02
      2. HTML title / UI markers: Nexus Repository Manager 3.90.1, ?_v=3.90.1-01
      3. JSON / status metadata: "version": "3.90.1"
    """
    if not text:
        return None

    patterns = [
        r'Nexus/([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[\.\-][0-9a-zA-Z]+)?',
        r'(?:Nexus\s+Repository(?:\s+Manager)?|Sonatype\s+Nexus)[^0-9\r\n]{1,25}v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[\.\-][0-9a-zA-Z]+)?\b',
        r'\?(?:_v|v|version)=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[\.\-][0-9a-zA-Z]+)?\b',
        r'"version"\s*:\s*"v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[\.\-][0-9a-zA-Z]+)?"',
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


def is_nexus_vulnerable(major: int, minor: int, patch: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates Sonatype Nexus Repository version against CVE-2026-113373
    (3.86.0 <= version < 3.98.0 is vulnerable).
    """
    ver_tuple = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if MIN_VULNERABLE_VERSION <= ver_tuple < FIXED_VERSION:
        return True, (
            f"Sonatype Nexus Repository {ver_display} is vulnerable to CVE-2026-113373 "
            f"(CVSS 9.1 SAML/OIDC disabled account status bypass; affected: 3.86.0 to 3.97.1, fixed in 3.98.0)."
        )

    return False, (
        f"Sonatype Nexus Repository {ver_display} is not affected by CVE-2026-113373 "
        f"(patched in >= 3.98.0 or prior to 3.86.0)."
    )


class NexusRepositoryAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Sonatype Nexus Repository 3 SAML/OIDC Account Status Bypass Audit (CVE-2026-113373).
    Performs safe, non-destructive HTTP/HTTPS fingerprinting of Nexus Repository 3 servers.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Sonatype Nexus Repository 3 SAML/OIDC Account Bypass Audit (CVE-2026-113373)",
            "description": "Audits HTTP/HTTPS endpoints (ports 8081, 80, 443, 8443) for Sonatype Nexus Repository 3 instances (3.86.0 to 3.97.1) vulnerable to SAML/OIDC disabled account status bypass (CVE-2026-113373).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-113373",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_NEXUS_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or Nexus Repository ports on the target host.
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
                    or "nexus" in s_name
                    or "sonatype" in s_name
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
        path: str = "/",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect Nexus headers and web UI.
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-113373)",
                "Accept": "text/html,application/json,*/*",
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
        Probes standard Nexus Repository paths (/service/rest/v1/status, /) to detect the service and version.
        """
        candidate_paths = ["/service/rest/v1/status", "/"]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            server_lower = server_hdr.lower()
            body_lower = body.lower()

            is_nexus = (
                "nexus/" in server_lower
                or "sonatype nexus" in body_lower
                or "nexus repository manager" in body_lower
                or ("nexus" in body_lower and "sonatype" in body_lower)
            )

            if not is_nexus:
                continue

            ver_info = parse_nexus_version(server_hdr) or parse_nexus_version(body)
            if ver_info:
                major, minor, patch, raw_str = ver_info
                is_vuln, reason = is_nexus_vulnerable(major, minor, patch, raw_str)
                return {
                    "port": port,
                    "nexus_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            return {
                "port": port,
                "nexus_detected": True,
                "version": "Concealed (Nexus version hidden)",
                "source": f"HTTP GET {path} (Sonatype Nexus interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"Sonatype Nexus Repository detected on port {port} ({path}), but exact version is concealed. "
                    f"Verify in the Administration > System Information console that Nexus Repository is updated to 3.98.0 or later."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified Nexus Repository ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("nexus_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Sonatype Nexus Repository v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] Sonatype Nexus Repository v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-113373 confirmed on {target_ip}.\n"
                f"Vulnerable Sonatype Nexus Repository instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-113373 - CVSS 9.1):\n"
                f"The target host {target_ip} runs a vulnerable Sonatype Nexus Repository 3 instance (3.86.0 to 3.97.1).\n"
                f"Flaw Overview:\n"
                f"Sonatype Nexus Repository 3 Pro does not check the local account status when a user signs in "
                f"through a configured SAML or OAuth2/OpenID Connect identity provider, allowing a disabled or "
                f"locked local user to regain an active session with full assigned roles.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Sonatype Nexus Repository 3 immediately to version 3.98.0 or later.\n"
                f"2. Ensure revoked accounts are also immediately disabled at the upstream SAML/OIDC Identity Provider."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Sonatype Nexus Repository active with concealed version."
            details = (
                f"Sonatype Nexus Repository detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Sonatype Nexus Repository instances on {target_ip} are running versions resistant to CVE-2026-113373:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable Sonatype Nexus Repository instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for Sonatype Nexus Repository CVE-2026-113373."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[8081, 80, 443, 8443],
        help="Ports to inspect (default: 8081 80 443 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-113373 Auditor (Sonatype Nexus)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = NexusRepositoryAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-113373!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual Nexus Repository version verification.\n")
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
