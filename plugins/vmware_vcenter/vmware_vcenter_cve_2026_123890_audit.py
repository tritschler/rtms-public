"""
vmware_vcenter_cve_2026_123890_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS SDK and UI version metadata verification
for VMware vCenter Server against the November 2026 Security Advisory:
  - CVE-2026-123890 (CVSS 9.8 Critical): Authentication bypass vulnerability in the VMware Directory Service (vmdir).

Affected Versions:
  - VMware vCenter Server 9.1.x: prior to 9.1.1.0200
  - VMware vCenter Server 9.0.x: prior to 9.0.2.0200
  - VMware vCenter Server 8.0.x: prior to 8.0 U3m (8.0.3.01300 / Update 3m)
  - VMware vCenter Server 5.x: prior to 5.2.5

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
                return self.format_result("Skipped", details="Requirements not met (no target VMware vCenter ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_VCENTER_PORTS = [443, 8443, 5480, 80, 8080]
SSL_PORTS = {443, 8443, 5480}


def parse_vcenter_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts VMware vCenter version tuple (major, minor, patch, build_or_sub, raw_str)
    from vCenter SDK vimServiceVersions.xml, REST API metadata, or UI descriptors.

    Supports both 4-part numeric versions (e.g. '9.1.1.0200', '9.0.1.0100', '5.2.4')
    and 8.0 Update notation (e.g. '8.0 U3l' -> (8, 0, 3, 12, '8.0 U3l'),
    '8.0 U3m' -> (8, 0, 3, 13, '8.0 U3m')).
    """
    if not text:
        return None

    # Check 8.0 Update notation first: e.g. 'vCenter Server 8.0 U3l' or '8.0 Update 3m'
    u_match = re.search(
        r"(?:vCenter(?:\s+Server)?|VMware)[^0-9\n]{0,30}\b(8)\.(0)(?:\.[0-9]+)?\s*(?:U|Update\s*)([0-9])([a-z])?\b",
        text,
        re.IGNORECASE,
    )
    if u_match:
        major = int(u_match.group(1))
        minor = int(u_match.group(2))
        upd_num = int(u_match.group(3))
        letter = (u_match.group(4) or "").lower()
        sub = (ord(letter) - ord("a") + 1) if letter else 0
        raw_str = f"8.0 U{upd_num}{letter}"
        return major, minor, upd_num, sub, raw_str

    patterns = [
        r"(?:vCenter(?:\s+Server)?|VMware\s+vCenter)[\s:/v\"'-]+([589])\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b",
        r'(?:<version>|"version"\s*:\s*")\s*([589])\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\s*(?:</version>|")',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            sub = int(match.group(4)) if match.group(4) is not None else 0
            raw_str = (
                f"{major}.{minor}.{patch}.{match.group(4)}"
                if match.group(4) is not None
                else f"{major}.{minor}.{patch}"
            )
            return major, minor, patch, sub, raw_str

    return None


def is_vcenter_version_vulnerable(
    major: int,
    minor: int,
    patch: int,
    sub: int = 0,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether a VMware vCenter Server version is affected by CVE-2026-123890 (CVSS 9.8).
    Affected:
      - 5.x prior to 5.2.5 (< (5, 2, 5, 0))
      - 8.0.x prior to 8.0 U3m (Update 3m -> (8, 0, 3, 13) or numeric < (8, 0, 3, 1300))
      - 9.0.x prior to 9.0.2.0200 (< (9, 0, 2, 200))
      - 9.1.x prior to 9.1.1.0200 (< (9, 1, 1, 200))
    """
    ver = (major, minor, patch, sub)
    ver_display = raw_str or f"{major}.{minor}.{patch}.{sub}"

    if major == 5:
        if ver < (5, 2, 5, 0):
            return True, (
                f"VMware vCenter {ver_display} is in the 5.x branch prior to 5.2.5 and is affected by "
                f"CVE-2026-123890 (CVSS 9.8)."
            )
        return False, f"VMware vCenter {ver_display} is patched in the 5.x branch (>= 5.2.5) against CVE-2026-123890."

    if major == 8 and minor == 0:
        # In Update notation, U3m maps to patch=3, sub=13 ('m' is 13th letter).
        # In 4-part numeric notation, 8.0.3.01300 has sub=1300.
        threshold_sub = 13 if sub < 100 else 1300
        if (major, minor, patch, sub) < (8, 0, 3, threshold_sub):
            return True, (
                f"VMware vCenter {ver_display} is in the 8.0 branch prior to 8.0 U3m and is affected by "
                f"CVE-2026-123890 (CVSS 9.8)."
            )
        return False, f"VMware vCenter {ver_display} is patched in the 8.0 branch (>= 8.0 U3m) against CVE-2026-123890."

    if major == 9 and minor == 0:
        if ver < (9, 0, 2, 200):
            return True, (
                f"VMware vCenter {ver_display} is in the 9.0.x branch prior to 9.0.2.0200 and is affected by "
                f"CVE-2026-123890 (CVSS 9.8)."
            )
        return False, (
            f"VMware vCenter {ver_display} is patched in the 9.0.x branch (>= 9.0.2.0200) against CVE-2026-123890."
        )

    if major == 9 and minor == 1:
        if ver < (9, 1, 1, 200):
            return True, (
                f"VMware vCenter {ver_display} is in the 9.1.x branch prior to 9.1.1.0200 and is affected by "
                f"CVE-2026-123890 (CVSS 9.8)."
            )
        return False, (
            f"VMware vCenter {ver_display} is patched in the 9.1.x branch (>= 9.1.1.0200) against CVE-2026-123890."
        )

    return False, f"VMware vCenter {ver_display} is not in an affected version range for CVE-2026-123890."


class VMwareVCenterAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: VMware vCenter Server Version Compliance Audit
    (CVE-2026-123890 - CVSS 9.8 Critical).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "VMware vCenter Server Directory Service Auth Bypass Audit (CVE-2026-123890)",
            "description": (
                "Passive version compliance check for VMware vCenter Server (9.1.x < 9.1.1.0200, "
                "9.0.x < 9.0.2.0200, 8.0 < 8.0 U3m, 5.x < 5.2.5) against CVE-2026-123890 (CVSS 9.8)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-123890",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_VCENTER_PORTS.copy()
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

                if port in self.target_ports or "vmware" in s_name or "vcenter" in s_name or "http" in s_name:
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
        path: str = "/sdk/vimServiceVersions.xml",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-123890)",
                "Accept": "application/xml,text/xml,application/json,text/html,*/*",
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
            logger.debug(f"vCenter HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/sdk/vimServiceVersions.xml", "vCenter SDK vimServiceVersions.xml"),
            ("/ui/", "vSphere Client Web UI"),
            ("/", "vCenter Root Landing Page"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            if "vmware" in combined.lower() or "vcenter" in combined.lower() or "vim25" in combined.lower():
                ver_info = parse_vcenter_version(combined)
                if ver_info:
                    major, minor, patch, sub, ver_str = ver_info
                    is_vuln, reason = is_vcenter_version_vulnerable(major, minor, patch, sub, ver_str)
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
                    f"- [{port_label}] VMware vCenter {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] VMware vCenter {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-123890 affected VMware vCenter Server detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-123890 - CVSS 9.8):\n"
                f"The target host {target_ip} exposes an unpatched VMware vCenter Server instance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-123890 (CVSS 9.8): Authentication bypass vulnerability in the VMware Directory Service (vmdir).\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade VMware vCenter Server to 9.1.1.0200+, 9.0.2.0200+, 8.0 U3m+, or 5.2.5+ (KB463116).\n"
                f"2. Restrict network access to vCenter management and Directory Service interfaces."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: VMware vCenter Server instance on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected VMware vCenter Server services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for VMware vCenter Server (CVE-2026-123890)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_VCENTER_PORTS,
        help="Ports to inspect (default: 443 8443 5480 80 8080)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = VMwareVCenterAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a VMware vCenter version affected by CVE-2026-123890.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
