"""
cyrus_sasl_cve_2026_129483_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only banner and capability verification for services using
Cyrus SASL (such as IMAP, POP3, SMTP, ManageSieve) to check patch compliance against:
  - CVE-2026-129483 (CVSS 9.3, affected: <= 2.1.28): Authentication bypass
    vulnerability in the Cyrus SASL SRP server mechanism (srp_server_mech_step2).

Fixed in: Cyrus SASL 2.1.29+ (or by disabling the SRP mechanism plugin).

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import socket
import ssl
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
                return self.format_result("Skipped", details="Requirements not met (no target SASL-capable services found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_SASL_PORTS = [25, 110, 143, 465, 587, 993, 995, 4190]
IMPLICIT_TLS_PORTS = {465, 993, 995}
SMTP_PORTS = {25, 465, 587}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}
SIEVE_PORTS = {4190}

MAX_VULNERABLE_VERSION = (2, 1, 28)
MIN_PATCHED_VERSION = (2, 1, 29)


def parse_cyrus_sasl_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Cyrus SASL semantic version (major, minor, patch, raw_str) from:
      - Service banners or capability strings: 'Cyrus SASL 2.1.28', 'cyrus-sasl/2.1.28', 'libsasl2 2.1.27'
    """
    if not text:
        return None

    patterns = [
        r"(?:cyrus[\s\-_]*sasl|libsasl2?)[\s/\-_v:]*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            ver_str = f"{major}.{minor}.{patch}"
            return major, minor, patch, ver_str

    return None


def has_srp_mechanism_advertised(text: str) -> bool:
    """
    Checks whether the service banner or capability response advertises the SASL SRP mechanism.
    Examples:
      - IMAP: 'CAPABILITY IMAP4rev1 ... AUTH=SRP ...'
      - SMTP: '250-AUTH PLAIN LOGIN SRP'
      - ManageSieve: '"SASL" "PLAIN SRP"'
    """
    if not text:
        return False

    patterns = [
        r"\bAUTH=SRP\b",
        r"250[\-\s]AUTH\b[^\r\n]*\bSRP\b",
        r'"SASL"\s+"[^"]*\bSRP\b[^"]*"',
        r"\bSASL\b[^\r\n]*\bSRP\b",
    ]
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


def is_cyrus_sasl_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Cyrus SASL version tuple (major, minor, patch) is affected by:
      - CVE-2026-129483 (<= 2.1.28)
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if ver_tuple <= MAX_VULNERABLE_VERSION:
        return True, (
            f"Cyrus SASL {ver_str} is affected by CVE-2026-129483 "
            f"(affected: <= 2.1.28; requires upgrade to Cyrus SASL >= 2.1.29 or disabling SRP)."
        )

    return False, (
        f"Cyrus SASL {ver_str} is patched against CVE-2026-129483 "
        f"(running >= 2.1.29)."
    )


class CyrusSaslAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Cyrus SASL SRP Authentication Bypass Compliance Audit (CVE-2026-129483).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Cyrus SASL SRP Authentication Bypass Audit (CVE-2026-129483)",
            "description": (
                "Passive version and SASL mechanism compliance check for Cyrus SASL <= 2.1.28 "
                "(CVE-2026-129483 — CVSS 9.3)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-129483",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_SASL_PORTS.copy()
        self.ssl_ports = sorted(list(IMPLICIT_TLS_PORTS))
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
                    or "imap" in s_name
                    or "pop3" in s_name
                    or "smtp" in s_name
                    or "sieve" in s_name
                    or "sasl" in s_name
                    or "cyrus" in s_name
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

    def probe_sasl_endpoint(
        self,
        target_ip: str,
        port: int,
        timeout: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        """
        Passively connects to a mail/directory port, reads the greeting banner, and requests
        standard read-only capability listings (EHLO / CAPABILITY / CAPA) if not already in the greeting.
        """
        use_implicit_tls = port in IMPLICIT_TLS_PORTS
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

            banner_bytes = conn_sock.recv(4096)
            banner = banner_bytes.decode("utf-8", errors="replace").strip()
            if not banner:
                return None

            capability_text = ""
            try:
                if port in SMTP_PORTS:
                    conn_sock.sendall(b"EHLO rtms-audit.local\r\n")
                    capability_text = conn_sock.recv(4096).decode("utf-8", errors="replace").strip()
                    conn_sock.sendall(b"QUIT\r\n")
                elif port in IMAP_PORTS:
                    if "CAPABILITY" not in banner.upper():
                        conn_sock.sendall(b"A001 CAPABILITY\r\n")
                        capability_text = conn_sock.recv(4096).decode("utf-8", errors="replace").strip()
                    conn_sock.sendall(b"A002 LOGOUT\r\n")
                elif port in POP3_PORTS:
                    conn_sock.sendall(b"CAPA\r\n")
                    capability_text = conn_sock.recv(4096).decode("utf-8", errors="replace").strip()
                    conn_sock.sendall(b"QUIT\r\n")
                elif port in SIEVE_PORTS:
                    conn_sock.sendall(b"LOGOUT\r\n")
            except Exception:
                pass

            combined = f"{banner}\n{capability_text}".strip()
            return {
                "port": port,
                "banner": banner,
                "capabilities": capability_text,
                "combined": combined,
            }
        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"SASL probe failed on {target_ip}:{port}: {e}")
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
        probe = self.probe_sasl_endpoint(target_ip, port, timeout=timeout)
        if not probe:
            return None

        combined = probe.get("combined", "")
        srp_advertised = has_srp_mechanism_advertised(combined)
        ver_info = parse_cyrus_sasl_version(combined)

        if ver_info:
            major, minor, patch, ver_str = ver_info
            is_vuln, reason = is_cyrus_sasl_version_vulnerable(major, minor, patch)
            if srp_advertised and is_vuln:
                reason += " Furthermore, the SASL SRP mechanism is actively advertised on this port."
            return {
                "port": port,
                "service_detected": True,
                "version": ver_str,
                "srp_advertised": srp_advertised,
                "source": f"Service Banner / Capabilities (Port {port})",
                "is_vulnerable": is_vuln,
                "reason": reason,
            }

        if srp_advertised:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "srp_advertised": True,
                "source": f"SASL Capability Advertisement (Port {port})",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Service actively advertises the SASL SRP mechanism with concealed Cyrus SASL library version. "
                    "Verify that Cyrus SASL is updated to >= 2.1.29 or disable the SRP plugin."
                ),
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        safe_findings: List[str] = []
        concealed_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("service_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Cyrus SASL {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Cyrus SASL {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated Cyrus SASL version detected on {target_ip} "
                f"(CVE-2026-129483).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (Cyrus SASL <= 2.1.28 - CVSS 9.3):\n"
                f"The target host {target_ip} exposes an unpatched version of Cyrus SASL.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-129483 (CVSS 9.3): Authentication bypass vulnerability in the Cyrus SASL "
                f"SRP mechanism (srp_server_mech_step2) in versions through 2.1.28.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Cyrus SASL (libsasl2) packages to version 2.1.29 or later (or apply vendor security backports).\n"
                f"2. Disable or remove the unused SASL SRP mechanism plugin (libsaslsrp) from sasl2 configuration."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "SASL SRP mechanism advertised with concealed library version."
            details = (
                f"SASL SRP authentication mechanism detected on {target_ip} with concealed Cyrus SASL version:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Cyrus SASL services on {target_ip} are running patched versions (>= 2.1.29):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Cyrus SASL services or exposed SRP mechanisms detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version and capability compliance check for Cyrus SASL (CVE-2026-129483)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_SASL_PORTS,
        help="Ports to inspect (default: 25 110 143 465 587 993 995 4190)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = CyrusSaslAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Cyrus SASL version affected by CVE-2026-129483.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} advertises SASL SRP requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
