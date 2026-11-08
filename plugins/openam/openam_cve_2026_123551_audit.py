"""
openam_cve_2026_123551_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 8080, 8443, 443, 80, 9443) for OpenAM
identity and access management servers (versions prior to 16.1.4) affected by:
  - CVE-2026-123551 (CVSS 10.0 Critical): Unauthenticated live session token
    (iPlanetDirectoryPro) disclosure via the notification WebSocket and
    unvalidated internal forward on legacy Liberty ID-FF endpoints (14.0.0 - 16.1.3).
  - CVE-2026-123550 (CVSS 9.3 Critical): SAML v2.0 Service Provider authentication
    bypass via unsigned assertions on ECP (PAOS) and HTTP-Artifact bindings (< 16.1.4).
  - CVE-2026-123549 (CVSS 9.3 Critical): Privilege escalation to administrative
    groups via unrestricted attributes in self-registration endpoints (< 16.1.4).

CVSS Score: 10.0 (Critical) - CWE-200 / CWE-287 / CWE-269
Affected Components: OpenAM < 16.1.4 (14.0.0 through 16.1.3).
Fixed in: OpenAM 16.1.4+.

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
                return self.format_result("Skipped", details="Requirements not met (no target OpenAM ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard OpenAM HTTP/HTTPS ports
DEFAULT_OPENAM_PORTS = [8080, 8443, 443, 80, 9443]
SSL_PORTS = {443, 8443, 9443}
FIXED_VERSION = (16, 1, 4)


def parse_openam_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts OpenAM version (major, minor, patch, raw_str) from:
      1. Server info JSON: {"version":"16.1.3","revision":"..."} or {"fullVersion":"OpenAM 16.1.3 ..."}
      2. Headers or HTML banners: OpenAM 16.1.3, OpenAM/16.1.3, X-OpenAM-Version: 16.1.3
      3. XUI static asset cache-busting parameter: ?v=16.1.3 or /XUI/?v=15.1.2
    """
    if not text:
        return None

    patterns = [
        r'"(?:fullVersion|version)"\s*:\s*"(?:OpenAM[\s/\-]*)?v?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?(?:[\.\-\s][0-9a-zA-Z._\-]*)?"',
        r'OpenAM[\s/\-:]+v?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?\b',
        r'\?v=([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?\b',
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


def is_openam_vulnerable(major: int, minor: int, patch: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates OpenAM version against CVE-2026-123551, CVE-2026-123550, and CVE-2026-123549
    (versions < 16.1.4 are vulnerable).
    """
    ver_tuple = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if ver_tuple < FIXED_VERSION:
        if major >= 14:
            return True, (
                f"OpenAM {ver_display} is affected by CVE-2026-123551 (CVSS 10.0 live session token leak "
                f"via notification WebSocket), CVE-2026-123550 (CVSS 9.3 SAML 2.0 ECP/Artifact auth bypass), "
                f"and CVE-2026-123549 (CVSS 9.3 self-registration admin group privilege escalation). "
                f"Fixed in 16.1.4."
            )
        return True, (
            f"OpenAM {ver_display} (< 16.1.4) is affected by CVE-2026-123550 (CVSS 9.3 SAML 2.0 auth bypass) "
            f"and CVE-2026-123549 (CVSS 9.3 self-registration privilege escalation). Fixed in 16.1.4."
        )

    return False, (
        f"OpenAM {ver_display} is not affected by CVE-2026-123551 / CVE-2026-123550 / CVE-2026-123549 "
        f"(patched in >= 16.1.4)."
    )


class OpenAMAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: OpenAM Session Token Disclosure & SAML Auth Bypass Audit
    (CVE-2026-123551 / CVE-2026-123550 / CVE-2026-123549).
    Performs safe, read-only HTTP/HTTPS fingerprinting of OpenAM identity servers.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "OpenAM Live Session Token Disclosure & Auth Bypass Audit (CVE-2026-123551)",
            "description": "Audits HTTP/HTTPS endpoints (ports 8080, 8443, 443, 80, 9443) for OpenAM instances (< 16.1.4) affected by unauthenticated live session token disclosure (CVE-2026-123551, CVSS 10.0), SAML v2.0 authentication bypass (CVE-2026-123550), and self-registration privilege escalation (CVE-2026-123549).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-123551",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_OPENAM_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or OpenAM SSO ports on the target host.
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
                    or "openam" in s_name
                    or "forgerock" in s_name
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
        Performs a read-only HTTP/HTTPS GET request to inspect OpenAM headers, serverinfo JSON, and XUI assets.
        """
        use_ssl = port in SSL_PORTS or port in (443, 8443, 9443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-123551)",
                "Accept": "application/json,text/html,application/xhtml+xml,*/*",
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
        Probes standard OpenAM endpoints (/openam/json/serverinfo/version, /am/json/serverinfo/version,
        /openam/XUI/, /openam/, /) to detect the service and release version.
        """
        candidate_paths = [
            "/openam/json/serverinfo/version",
            "/am/json/serverinfo/version",
            "/openam/XUI/",
            "/openam/",
            "/"
        ]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            openam_ver_hdr = headers.get("x-openam-version", "")
            set_cookie = headers.get("set-cookie", "")
            location_hdr = headers.get("location", "")
            body_lower = body.lower()

            is_openam = (
                "openam" in body_lower
                or "openam" in server_hdr.lower()
                or bool(openam_ver_hdr)
                or "iplanetdirectorypro" in body_lower
                or "iplanetdirectorypro" in set_cookie.lower()
                or "amlbcookie" in set_cookie.lower()
                or "/openam/" in location_hdr.lower()
                or ("/json/serverinfo/" in path and '"version"' in body_lower and '"revision"' in body_lower)
            )

            if not is_openam:
                continue

            ver_info = (
                parse_openam_version(openam_ver_hdr)
                or parse_openam_version(server_hdr)
                or parse_openam_version(body)
                or parse_openam_version(location_hdr)
            )
            if ver_info:
                major, minor, patch, raw_str = ver_info
                is_vuln, reason = is_openam_vulnerable(major, minor, patch, raw_str)
                return {
                    "port": port,
                    "openam_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            return {
                "port": port,
                "openam_detected": True,
                "version": "Concealed (OpenAM version hidden)",
                "source": f"HTTP GET {path} (OpenAM identity interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"OpenAM detected on port {port} ({path}), but exact version is concealed. "
                    f"Verify in the OpenAM Administration Console that the server is updated to 16.1.4 or later."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified OpenAM ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("openam_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] OpenAM v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] OpenAM v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-123551 / CVE-2026-123550 / CVE-2026-123549 confirmed on {target_ip}.\n"
                f"Vulnerable OpenAM instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-123551 CVSS 10.0 / CVE-2026-123550 CVSS 9.3 / CVE-2026-123549 CVSS 9.3):\n"
                f"The target host {target_ip} runs a vulnerable OpenAM instance (< 16.1.4).\n"
                f"Flaw Overview:\n"
                f"1. CVE-2026-123551 (CVSS 10.0): Unauthenticated attackers can bypass the agent-only check via an "
                f"unvalidated internal forward on legacy Liberty ID-FF endpoints to read live iPlanetDirectoryPro "
                f"session tokens from the notification WebSocket, hijacking user and administrator sessions.\n"
                f"2. CVE-2026-123550 (CVSS 9.3): SAML v2.0 Service Provider accepts unsigned assertions on ECP (PAOS) "
                f"and HTTP-Artifact bindings when WantAssertionsSigned is false.\n"
                f"3. CVE-2026-123549 (CVSS 9.3): Self-registration endpoints fail to enforce the Valid Creation "
                f"Attributes list, allowing anonymous attackers to join administrative groups.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately upgrade OpenAM to version 16.1.4 or later.\n"
                f"2. Restrict external access to legacy Liberty ID-FF endpoints and notification WebSockets at the reverse proxy.\n"
                f"3. Enforce WantAssertionsSigned=true on SAML v2.0 SP configurations and disable anonymous self-registration if unused."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "OpenAM active with concealed version."
            details = (
                f"OpenAM detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: OpenAM instances on {target_ip} are running versions resistant to CVE-2026-123551:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable OpenAM instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for OpenAM CVE-2026-123551 / CVE-2026-123550 / CVE-2026-123549."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[8080, 8443, 443, 80, 9443],
        help="Ports to inspect (default: 8080 8443 443 80 9443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-123551 Auditor (OpenAM)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = OpenAMAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-123551!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual OpenAM version verification.\n")
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
