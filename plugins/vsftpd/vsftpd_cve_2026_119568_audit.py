"""
vsftpd_cve_2026_119568_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits FTP and FTPS endpoints (ports 21, 990, 2121, 8021) for vsftpd servers
(versions <= 3.0.5) vulnerable to FTPS Data Channel Hijacking & Authentication Bypass
in ssl_data_accept() via TLS session ticket resumption (CVE-2026-119568).

CVSS Score: 9.1 (Critical) - CWE-287 (Improper Authentication) / CWE-384 (Session Fixation)
Affected Components: vsftpd (Very Secure FTP Daemon) through 3.0.5.
Fixed in: vsftpd 3.0.6+.

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import socket
import ssl
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
                return self.format_result("Skipped", details="Requirements not met (no target FTP/FTPS services found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Common ports serving FTP / FTPS
DEFAULT_FTP_PORTS = [21, 990, 2121, 8021]
IMPLICIT_FTPS_PORTS = {990}

# Vulnerability threshold: vsftpd <= 3.0.5 is vulnerable; fixed in 3.0.6+
MAX_VULNERABLE_VERSION = (3, 0, 5)
MIN_PATCHED_VERSION = (3, 0, 6)


def parse_vsftpd_version(banner: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts vsftpd semantic version (major, minor, patch, raw_str) from FTP banners.
    Examples:
      '220 (vsFTPd 3.0.5)' -> (3, 0, 5, '3.0.5')
      '220-Welcome to vsftpd 3.0.3-ubuntu1' -> (3, 0, 3, '3.0.3')
      'vsFTPd 2.3.4' -> (2, 3, 4, '2.3.4')
    """
    if not banner:
        return None

    pattern = r"vsftpd[\s/\-_v]*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?"
    match = re.search(pattern, banner, re.IGNORECASE)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) is not None else 0
        raw_ver = f"{major}.{minor}.{patch}"
        return major, minor, patch, raw_ver

    return None


def is_vsftpd_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates vsftpd version tuple against CVE-2026-119568 boundary (<= 3.0.5 is vulnerable).
    Returns (is_vulnerable, explanation).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if ver_tuple <= MAX_VULNERABLE_VERSION:
        return True, (
            f"vsftpd {ver_str} is vulnerable to CVE-2026-119568 "
            f"(affected: <= 3.0.5; requires >= 3.0.6). "
            f"ssl_data_accept() fails to bind FTPS data channel TLS session tickets to the "
            f"authenticated control session, allowing unauthenticated PASV data connection hijacking."
        )

    return False, (
        f"vsftpd {ver_str} is patched against CVE-2026-119568 "
        f"(running >= 3.0.6)."
    )


class VsftpdFTPSHijackAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: vsftpd FTPS Data Channel Hijacking & Auth Bypass Audit (CVE-2026-119568).
    Performs safe, non-destructive FTP/FTPS banner inspection and AUTH TLS capability probing
    to detect vulnerable vsftpd instances (<= 3.0.5).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "vsftpd FTPS Data Channel Hijacking Audit (CVE-2026-119568)",
            "description": "Audits FTP/FTPS services (ports 21, 990, 2121, 8021) for vsftpd <= 3.0.5 vulnerable to unauthenticated FTPS data connection hijacking in ssl_data_accept() via TLS session ticket resumption (CVE-2026-119568).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-119568",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_FTP_PORTS.copy()
        self.ssl_ports = sorted(list(IMPLICIT_FTPS_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers FTP or FTPS ports on the target host.
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
                    or "ftp" in s_name
                    or "ftps" in s_name
                    or "vsftpd" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (21, 990, 2121, 8021):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_ftp_endpoint(
        self,
        target_ip: str,
        port: int,
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Safely connects to an FTP/FTPS port, reads the 220 welcome banner, and checks
        whether explicit FTPS ('AUTH TLS') or implicit FTPS is supported.
        """
        use_implicit_tls = port in IMPLICIT_FTPS_PORTS
        raw_sock = None
        conn_sock = None

        try:
            raw_sock = socket.create_connection((target_ip, port), timeout=timeout)
            if use_implicit_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn_sock = ctx.wrap_socket(raw_sock, server_hostname=target_ip)
            else:
                conn_sock = raw_sock

            banner_bytes = conn_sock.recv(2048)
            banner = banner_bytes.decode("utf-8", errors="replace").strip()
            if not banner:
                return None

            auth_tls_supported = use_implicit_tls
            auth_tls_response = "Implicit FTPS (TLS handshake succeeded)" if use_implicit_tls else ""

            if not use_implicit_tls:
                try:
                    conn_sock.sendall(b"AUTH TLS\r\n")
                    resp_bytes = conn_sock.recv(2048)
                    auth_tls_response = resp_bytes.decode("utf-8", errors="replace").strip()
                    if auth_tls_response.startswith("234"):
                        auth_tls_supported = True
                except Exception:
                    pass

                # Send QUIT politely if still in plaintext mode (when AUTH TLS was rejected)
                if not auth_tls_supported:
                    try:
                        conn_sock.sendall(b"QUIT\r\n")
                    except Exception:
                        pass

            return {
                "port": port,
                "banner": banner,
                "auth_tls_supported": auth_tls_supported,
                "auth_tls_response": auth_tls_response
            }

        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"FTP probe failed on {target_ip}:{port}: {e}")
            return None
        finally:
            if conn_sock:
                try:
                    conn_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        """
        Evaluates an FTP/FTPS port for vsftpd version and AUTH TLS exposure to CVE-2026-119568.
        """
        probe = self.probe_ftp_endpoint(target_ip, port, timeout=timeout)
        if not probe:
            return None

        banner = probe.get("banner", "")
        auth_tls = bool(probe.get("auth_tls_supported", False))
        auth_resp = probe.get("auth_tls_response", "")

        ver_info = parse_vsftpd_version(banner)
        if ver_info:
            major, minor, patch, ver_str = ver_info
            is_vuln_ver, ver_reason = is_vsftpd_version_vulnerable(major, minor, patch)

            if is_vuln_ver and auth_tls:
                return {
                    "port": port,
                    "ftp_detected": True,
                    "vsftpd_detected": True,
                    "version": ver_str,
                    "banner": banner,
                    "auth_tls_supported": True,
                    "auth_tls_response": auth_resp,
                    "is_vulnerable": True,
                    "reason": (
                        f"{ver_reason} FTPS is active on port {port} ({auth_resp}), "
                        f"making ssl_data_accept() directly reachable."
                    )
                }

            if is_vuln_ver and not auth_tls:
                return {
                    "port": port,
                    "ftp_detected": True,
                    "vsftpd_detected": True,
                    "version": ver_str,
                    "banner": banner,
                    "auth_tls_supported": False,
                    "auth_tls_response": auth_resp,
                    "is_vulnerable": False,
                    "mitigated": True,
                    "reason": (
                        f"vsftpd {ver_str} binary is an affected version (<= 3.0.5), but explicit FTPS "
                        f"('AUTH TLS') was rejected ({auth_resp or 'disabled'}). Upgrade to vsftpd >= 3.0.6 "
                        f"before enabling ssl_enable=YES."
                    )
                }

            return {
                "port": port,
                "ftp_detected": True,
                "vsftpd_detected": True,
                "version": ver_str,
                "banner": banner,
                "auth_tls_supported": auth_tls,
                "auth_tls_response": auth_resp,
                "is_vulnerable": False,
                "reason": ver_reason
            }

        # Check if an FTP server with AUTH TLS enabled conceals its banner (ftpd_banner directive)
        if banner.startswith("220") and auth_tls:
            # Exclude other well-known FTP daemons if explicitly named in banner
            banner_lower = banner.lower()
            other_daemons = ("pure-ftpd", "proftpd", "filezilla", "microsoft ftp", "wing ftp", "ws_ftp")
            if not any(d in banner_lower for d in other_daemons):
                return {
                    "port": port,
                    "ftp_detected": True,
                    "vsftpd_detected": False,
                    "concealed": True,
                    "version": "Concealed (custom ftpd_banner)",
                    "banner": banner,
                    "auth_tls_supported": True,
                    "auth_tls_response": auth_resp,
                    "is_vulnerable": False,
                    "reason": (
                        f"FTPS service active on port {port} ('{auth_resp}') with a custom/concealed "
                        f"banner ('{banner}'). If this host runs vsftpd, verify that it is updated to >= 3.0.6."
                    )
                }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified FTP/FTPS ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        warning_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("ftp_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] vsftpd {result.get('version')} (Banner: '{result.get('banner')}', "
                    f"FTPS: '{result.get('auth_tls_response')}'). Result: {result.get('reason')}"
                )
            elif result.get("mitigated") or result.get("concealed"):
                warning_findings.append(
                    f"- [{port_label}] {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] vsftpd {result.get('version')} (Banner: '{result.get('banner')}'). "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-119568 confirmed on {target_ip}.\n"
                f"Vulnerable vsftpd FTPS services detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-119568 - CVSS 9.1):\n"
                f"The target host {target_ip} runs vsftpd <= 3.0.5 with FTPS (SSL/TLS) enabled.\n"
                f"Flaw Overview: vsftpd through 3.0.5 contains an authentication bypass vulnerability in "
                f"ssl_data_accept() that allows unauthenticated attackers to hijack FTPS data connections "
                f"by resuming their own TLS session ticket. Attackers sharing the victim's source IP (e.g. "
                f"behind shared NAT, carrier-grade NAT, VPN concentrator, or cloud egress gateway) can obtain "
                f"a TLS session ticket via AUTH TLS and connect to the victim's PASV data port to steal "
                f"downloads or inject malicious upload data.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade vsftpd to version 3.0.6 or apply your Linux distribution's security patch for CVE-2026-119568.\n"
                f"2. Ensure 'require_ssl_reuse=YES' is enforced in /etc/vsftpd.conf so data connections must reuse the control channel's exact TLS session.\n"
                f"3. Where possible, migrate file transfers from FTPS to SFTP (OpenSSH)."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if warning_findings and not safe_findings:
            proof = "vsftpd / FTPS service requires manual verification."
            details = (
                f"FTP/FTPS service flagged for manual verification on {target_ip}:\n"
                + "\n".join(warning_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: vsftpd services on {target_ip} are running patched versions (>= 3.0.6) "
                f"resistant to CVE-2026-119568:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable vsftpd FTPS instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit FTP/FTPS endpoints for vsftpd FTPS Data Channel Hijacking vulnerability (CVE-2026-119568)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[21, 990, 2121],
        help="Ports to inspect (default: 21 990 2121)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="Socket timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-119568 Auditor (vsftpd FTPS)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = VsftpdFTPSHijackAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-119568!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual verification.\n")
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
