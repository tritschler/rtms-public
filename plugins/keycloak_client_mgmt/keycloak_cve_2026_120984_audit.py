"""
keycloak_cve_2026_120984_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 8080, 8443, 443, 80) for Keycloak and
Red Hat Build of Keycloak instances (versions prior to 26.2.5) affected by
CVE-2026-120984 (Client Management Authorization Services Session Attribute
Bypass & Malicious JavaScript Policy Upload RCE).

CVSS Score: 9.1 (Critical) - CWE-94 / CWE-284 (Code Injection / Improper Access Control)
Affected Components: Keycloak / Red Hat Build of Keycloak < 26.2.5, Red Hat Single Sign-On 7.x.
Fixed in: Keycloak 26.2.5+.

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
                return self.format_result("Skipped", details="Requirements not met (no target Keycloak ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard Keycloak web ports
DEFAULT_KEYCLOAK_PORTS = [8080, 8443, 443, 80]
SSL_PORTS = {443, 8443}
FIXED_VERSION = (26, 2, 5)


def parse_keycloak_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Keycloak version (major, minor, patch, raw_str) from:
      1. Static resource asset paths: /resources/26.2.1/common/keycloak/...
      2. Server header or HTML metadata: Keycloak 26.2.1, Keycloak/26.2.1
      3. JSON / system info attributes: "version": "26.2.1"
    """
    if not text:
        return None

    patterns = [
        r'/resources/v?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?(?:[\.\-][0-9a-zA-Z]+)?/',
        r'Keycloak[/\s:]+v?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?(?:[\.\-][0-9a-zA-Z]+)?\b',
        r'(?:Red\s+Hat\s+Build\s+of\s+Keycloak|RH-SSO)[^0-9\r\n]{1,20}v?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?\b',
        r'"version"\s*:\s*"v?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?(?:[\.\-][0-9a-zA-Z]+)?"',
        r'^v?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?$',
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


def is_keycloak_cve_120984_vulnerable(major: int, minor: int, patch: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates Keycloak version against CVE-2026-120984
    (versions < 26.2.5 are vulnerable).
    """
    ver_tuple = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if ver_tuple < FIXED_VERSION:
        return True, (
            f"Keycloak {ver_display} is affected by CVE-2026-120984 "
            f"(CVSS 9.1 Client Management session attribute bypass & JavaScript policy upload RCE; fixed in 26.2.5)."
        )

    return False, (
        f"Keycloak {ver_display} is not affected by CVE-2026-120984 "
        f"(patched in >= 26.2.5)."
    )


class KeycloakClientMgmtAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Keycloak Client Management JS Policy RCE Audit (CVE-2026-120984).
    Performs safe, read-only HTTP/HTTPS fingerprinting of Keycloak identity servers.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Keycloak Client Management JS Policy Upload RCE Audit (CVE-2026-120984)",
            "description": "Audits HTTP/HTTPS endpoints (ports 8080, 8443, 443, 80) for Keycloak instances (< 26.2.5) affected by Client Management session attribute bypass and JavaScript policy RCE (CVE-2026-120984).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-120984",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_KEYCLOAK_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or Keycloak ports on the target host.
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
                    or "keycloak" in s_name
                    or "sso" in s_name
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
        Performs a read-only HTTP/HTTPS GET request to inspect Keycloak headers, static asset paths, and realm metadata.
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-120984)",
                "Accept": "text/html,application/json,application/xml,*/*",
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
        Probes standard Keycloak endpoints (/admin/master/console/, /realms/master/.well-known/openid-configuration, /)
        to detect the service and release version.
        """
        candidate_paths = [
            "/admin/master/console/",
            "/realms/master/.well-known/openid-configuration",
            "/auth/realms/master/.well-known/openid-configuration",
            "/"
        ]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            location_hdr = headers.get("location", "")
            body_lower = body.lower()
            loc_lower = location_hdr.lower()

            is_keycloak = (
                "keycloak" in body_lower
                or "keycloak" in server_hdr.lower()
                or "/realms/" in loc_lower
                or ("issuer" in body_lower and "/realms/" in body_lower and "authorization_endpoint" in body_lower)
                or "kc-header" in body_lower
            )

            if not is_keycloak:
                continue

            ver_info = (
                parse_keycloak_version(server_hdr)
                or parse_keycloak_version(body)
                or parse_keycloak_version(location_hdr)
            )
            if ver_info:
                major, minor, patch, raw_str = ver_info
                is_vuln, reason = is_keycloak_cve_120984_vulnerable(major, minor, patch, raw_str)
                return {
                    "port": port,
                    "keycloak_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            return {
                "port": port,
                "keycloak_detected": True,
                "version": "Concealed (Keycloak version hidden)",
                "source": f"HTTP GET {path} (Keycloak identity interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"Keycloak detected on port {port} ({path}), but exact version is concealed. "
                    f"Verify in the Keycloak Admin Console (Server Info) that the server is updated to 26.2.5 or later."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified Keycloak ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("keycloak_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Keycloak v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] Keycloak v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-120984 confirmed on {target_ip}.\n"
                f"Vulnerable Keycloak instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-120984 - CVSS 9.1):\n"
                f"The target host {target_ip} runs a vulnerable Keycloak instance (< 26.2.5).\n"
                f"Flaw Overview:\n"
                f"When a client is created or imported with authorization services enabled in Keycloak's "
                f"client management component, the server fails to clear an internal session attribute used "
                f"during setup. This allows an authenticated attacker with client management permissions to "
                f"bypass security controls and upload a malicious JavaScript policy executed on the server.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Keycloak / Red Hat Build of Keycloak immediately to version 26.2.5 or later.\n"
                f"2. Ensure script upload features (--features-disabled=scripts) remain disabled and audit manage-clients role assignments."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Keycloak active with concealed version."
            details = (
                f"Keycloak detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Keycloak instances on {target_ip} are running versions resistant to CVE-2026-120984:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable Keycloak instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for Keycloak CVE-2026-120984."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[8080, 8443, 443, 80],
        help="Ports to inspect (default: 8080 8443 443 80)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-120984 Auditor (Keycloak)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = KeycloakClientMgmtAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-120984!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual Keycloak version verification.\n")
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
