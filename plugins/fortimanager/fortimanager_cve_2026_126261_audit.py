"""
fortimanager_cve_2026_126261_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner, web UI metadata, and TLS certificate
verification for Fortinet FortiManager appliances to check patch compliance against:
  - CVE-2026-126261 (CVSS 9.8 Critical): Improper authorization vulnerability in
    FortiManager FGFM management protocol service.

Affected Versions:
  - FortiManager 8.0.0 (Fixed in 8.0.1+)
  - FortiManager 7.6.0 through 7.6.7 (Fixed in 7.6.8+)
  - FortiManager 7.4.0 through 7.4.5 (Fixed in 7.4.6+)
  - FortiManager 7.2.0 through 7.2.8 (Fixed in 7.2.9+)

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
                return self.format_result("Skipped", details="Requirements not met (no target FortiManager ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_FMG_PORTS = [443, 541, 80, 8443]
SSL_PORTS = {443, 541, 8443, 9443}


def parse_fortimanager_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts FortiManager version tuple (major, minor, patch, raw_version_str)
    from HTTP responses, static asset paths, or administrative login banners.
    Examples:
      - 'FortiManager v7.6.5-build3412' -> (7, 6, 5, '7.6.5')
      - 'fmg_version: "7.4.4"' -> (7, 4, 4, '7.4.4')
      - 'FortiManager-VM64 v8.0.0' -> (8, 0, 0, '8.0.0')
    """
    if not text:
        return None

    patterns = [
        r"FortiManager(?:-[A-Za-z0-9_]+)?\s+v?([78])\.([0-9]+)\.([0-9]+)",
        r"(?:fmg_version|FMG_VERSION|version_str|ver)\s*[:=]\s*[\"']?v?([78])\.([0-9]+)\.([0-9]+)",
        r"/flatui/[a-z0-9_-]*v([78])\.([0-9]+)\.([0-9]+)",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            ver_str = f"{major}.{minor}.{patch}"
            return major, minor, patch, ver_str

    return None


def is_fortimanager_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a FortiManager version (major, minor, patch) is affected by CVE-2026-126261.
      - 7.2.0 through 7.2.8 -> Vulnerable (Fixed in 7.2.9+)
      - 7.4.0 through 7.4.5 -> Vulnerable (Fixed in 7.4.6+)
      - 7.6.0 through 7.6.7 -> Vulnerable (Fixed in 7.6.8+)
      - 8.0.0               -> Vulnerable (Fixed in 8.0.1+)
    """
    ver_str = f"{major}.{minor}.{patch}"

    if (major, minor) == (7, 2):
        if 0 <= patch <= 8:
            return True, f"FortiManager {ver_str} is in the affected range 7.2.0–7.2.8 for CVE-2026-126261 (upgrade to >= 7.2.9)."
        return False, f"FortiManager {ver_str} is patched (>= 7.2.9) against CVE-2026-126261."

    if (major, minor) == (7, 4):
        if 0 <= patch <= 5:
            return True, f"FortiManager {ver_str} is in the affected range 7.4.0–7.4.5 for CVE-2026-126261 (upgrade to >= 7.4.6)."
        return False, f"FortiManager {ver_str} is patched (>= 7.4.6) against CVE-2026-126261."

    if (major, minor) == (7, 6):
        if 0 <= patch <= 7:
            return True, f"FortiManager {ver_str} is in the affected range 7.6.0–7.6.7 for CVE-2026-126261 (upgrade to >= 7.6.8)."
        return False, f"FortiManager {ver_str} is patched (>= 7.6.8) against CVE-2026-126261."

    if (major, minor) == (8, 0):
        if patch == 0:
            return True, f"FortiManager {ver_str} is affected by CVE-2026-126261 (upgrade to >= 8.0.1)."
        return False, f"FortiManager {ver_str} is patched (>= 8.0.1) against CVE-2026-126261."

    return False, f"FortiManager {ver_str} is outside the affected branches (7.2, 7.4, 7.6, 8.0) for CVE-2026-126261."


class FortiManagerAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Fortinet FortiManager Compliance Audit (CVE-2026-126261).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Fortinet FortiManager Version Compliance Audit (CVE-2026-126261)",
            "description": (
                "Passive version and FGFM service exposure check for Fortinet FortiManager "
                "against CVE-2026-126261 (CVSS 9.8 improper authorization)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-126261",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_FMG_PORTS.copy()
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
                    or "fgfm" in s_name
                    or "forti" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 541, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/p/login/",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-126261)",
                "Accept": "text/html,application/json,*/*",
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

    def probe_fgfm_tls(self, target_ip: str, port: int = 541, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        """
        Passively performs a standard TLS handshake on port 541 (FGFM) without sending any
        protocol payload, inspecting only peer TLS certificate metadata if provided.
        """
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target_ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=target_ip) as ssock:
                    cipher = ssock.cipher()
                    return {
                        "port": port,
                        "fgfm_reachable": True,
                        "cipher": cipher[0] if cipher else "TLS",
                    }
        except Exception as e:
            logger.debug(f"FGFM TLS check failed on {target_ip}:{port}: {e}")
            return None

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        if port == 541:
            fgfm = self.probe_fgfm_tls(target_ip, port=port, timeout=timeout)
            if fgfm and fgfm.get("fgfm_reachable"):
                return {
                    "port": port,
                    "service_detected": True,
                    "version": "Concealed (FGFM TLS Port 541 Open)",
                    "source": "FGFM TLS Handshake (Port 541)",
                    "is_vulnerable": False,
                    "concealed": True,
                    "reason": (
                        "FortiManager FGFM port 541/TCP is reachable over the network. "
                        "Verify that the appliance runs FortiManager >= 7.2.9, >= 7.4.6, >= 7.6.8, or >= 8.0.1 "
                        "and that `fgfm-deny-unknown` is enabled."
                    ),
                }
            return None

        candidate_paths = [
            ("/p/login/", "FortiManager /p/login/ web portal"),
            ("/cgi-bin/module/flatui_auth", "FortiManager flatui_auth endpoint"),
            ("/", "FortiManager HTTP root"),
        ]

        fmg_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"
            combined_lower = combined.lower()

            if (
                "fortimanager" in combined_lower
                or "flatui_auth" in combined_lower
                or "fmg_version" in combined_lower
                or ("fortinet" in combined_lower and "/p/login" in combined_lower)
            ):
                fmg_detected = True
                detected_source = source_label

                ver_info = parse_fortimanager_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_fortimanager_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if fmg_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "FortiManager web management interface is active, but the exact firmware version "
                    "is concealed in unauthenticated responses. Verify firmware >= 7.2.9 / 7.4.6 / 7.6.8 / 8.0.1."
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
                    f"- [{port_label}] FortiManager {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] FortiManager {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-126261 affected Fortinet FortiManager version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-126261 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an affected Fortinet FortiManager release.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-126261 (CVSS 9.8): Improper authorization vulnerability in FortiManager "
                f"(7.2.0–7.2.8, 7.4.0–7.4.5, 7.6.0–7.6.7, 8.0.0) affecting the FGFM management service.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade FortiManager to version 7.2.9+, 7.4.6+, 7.6.8+, or 8.0.1+.\n"
                f"2. Restrict network access to the FGFM port (541/TCP) via local-in policies to known FortiGate IPs.\n"
                f"3. Enable `set fgfm-deny-unknown enable` under `config system global`."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "FortiManager service detected (version concealed or FGFM port 541 exposed)."
            details = (
                f"FortiManager service detected on {target_ip}; manual firmware verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: FortiManager instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Fortinet FortiManager services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Fortinet FortiManager (CVE-2026-126261)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_FMG_PORTS,
        help="Ports to inspect (default: 443 541 80 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = FortiManagerAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a FortiManager version affected by CVE-2026-126261.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes FortiManager services requiring firmware verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
