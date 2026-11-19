"""
f5_bigip_cve_2026_123637_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS TMUI and iControl REST version metadata verification
for F5 BIG-IP appliances against the November 2026 F5 Quarterly Security Notification (7 CVEs):
  - CVE-2026-123637 (CVSS 9.3 Critical): BIG-IP APM per-request policy TMM termination and potential RCE.
  - CVE-2026-120722 (CVSS 9.3 Critical): BIG-IP DNS::scrape iRule TMM termination and potential RCE.
  - CVE-2026-121805 (CVSS 9.3 Critical): BIG-IP PEM::subscriber iRule TMM termination and potential RCE.
  - CVE-2026-116953 (CVSS 9.3 Critical): BIG-IP GENERICMESSAGE::route iRule TMM termination and potential RCE.
  - CVE-2026-120292 (CVSS 9.3 Critical): BIG-IP MR::message route iRule TMM termination and potential RCE.
  - CVE-2026-120285 (CVSS 9.3 Critical): BIG-IP PSC::ip_address iRule TMM termination and potential RCE.
  - CVE-2026-120718 (CVSS 9.2 Critical): BIG-IP iControl REST token expiration failure.

Affected Versions:
  - F5 BIG-IP 17.1.x: 17.1.0 through < 17.1.3.6 (Patched in 17.1.3.6)
  - F5 BIG-IP 17.5.x: 17.5.0 through < 17.5.1.10 (Patched in 17.5.1.10)
  - F5 BIG-IP 21.1.x: 21.1.0 through < 21.1.0.2 (Patched in 21.1.0.2)

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
                return self.format_result("Skipped", details="Requirements not met (no target F5 BIG-IP ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_BIGIP_PORTS = [443, 8443, 4353, 80]
SSL_PORTS = {443, 8443, 4353}


def parse_bigip_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts F5 BIG-IP TMOS 4-part version tuple (v1, v2, v3, v4, raw_str)
    from TMUI login page, headers, or iControl REST metadata.

    Examples:
      - 'BIG-IP 17.5.1.4 Build 0.0.12' -> (17, 5, 1, 4, '17.5.1.4')
      - 'BIG-IP release 17.1.3' -> (17, 1, 3, 0, '17.1.3')
      - '"version": "21.1.0.1"' -> (21, 1, 0, 1, '21.1.0.1')
    """
    if not text:
        return None

    patterns = [
        r"BIG-IP(?:\s+(?:release|version|TMOS|v))?[\s:/v-]+([12][0-9])\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,2}))?\b",
        r'(?:"version"\s*:\s*"|Version:\s*)([12][0-9])\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,2}))?\b',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            v1 = int(match.group(1))
            v2 = int(match.group(2))
            v3 = int(match.group(3))
            v4 = int(match.group(4)) if match.group(4) is not None else 0
            raw_str = f"{v1}.{v2}.{v3}.{v4}" if match.group(4) is not None else f"{v1}.{v2}.{v3}"
            return v1, v2, v3, v4, raw_str

    return None


def is_bigip_version_vulnerable(
    v1: int,
    v2: int,
    v3: int,
    v4: int = 0,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether an F5 BIG-IP version is affected by the November 2026 critical advisories:
      - CVE-2026-123637 (CVSS 9.3), CVE-2026-120722 (9.3), CVE-2026-121805 (9.3),
        CVE-2026-116953 (9.3), CVE-2026-120292 (9.3), CVE-2026-120285 (9.3), CVE-2026-120718 (9.2).
    Affected branches:
      - 17.1.x: 17.1.0 .. < 17.1.3.6
      - 17.5.x: 17.5.0 .. < 17.5.1.10
      - 21.1.x: 21.1.0 .. < 21.1.0.2
    """
    ver = (v1, v2, v3, v4)
    ver_display = raw_str or f"{v1}.{v2}.{v3}.{v4}"
    all_cves = (
        "CVE-2026-123637, CVE-2026-120722, CVE-2026-121805, "
        "CVE-2026-116953, CVE-2026-120292, CVE-2026-120285, and CVE-2026-120718"
    )

    if (v1, v2) == (17, 1):
        if ver < (17, 1, 3, 6):
            return True, (
                f"F5 BIG-IP {ver_display} is in the 17.1.x branch prior to 17.1.3.6 and is affected by "
                f"{all_cves} (CVSS 9.3)."
            )
        return False, f"F5 BIG-IP {ver_display} is patched in the 17.1.x branch (>= 17.1.3.6)."

    if (v1, v2) == (17, 5):
        if ver < (17, 5, 1, 10):
            return True, (
                f"F5 BIG-IP {ver_display} is in the 17.5.x branch prior to 17.5.1.10 and is affected by "
                f"{all_cves} (CVSS 9.3)."
            )
        return False, f"F5 BIG-IP {ver_display} is patched in the 17.5.x branch (>= 17.5.1.10)."

    if (v1, v2) == (21, 1):
        if ver < (21, 1, 0, 2):
            return True, (
                f"F5 BIG-IP {ver_display} is in the 21.1.x branch prior to 21.1.0.2 and is affected by "
                f"{all_cves} (CVSS 9.3)."
            )
        return False, f"F5 BIG-IP {ver_display} is patched in the 21.1.x branch (>= 21.1.0.2)."

    if (v1, v2) < (17, 1):
        return True, (
            f"F5 BIG-IP {ver_display} is an End of Technical Support (EoTS) release (< 17.1.0) "
            f"lacking November 2026 security fixes for {all_cves}."
        )

    if (17, 1) < (v1, v2) < (17, 5):
        return True, (
            f"F5 BIG-IP {ver_display} is an intermediate 17.x release prior to 17.5.1.10 and is affected by "
            f"{all_cves} (CVSS 9.3)."
        )

    return False, f"F5 BIG-IP {ver_display} is outside affected branches."


class F5BigIpAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: F5 BIG-IP TMOS & APM/iControl REST Version Compliance Audit
    (CVE-2026-123637, CVE-2026-120722, CVE-2026-121805, CVE-2026-116953,
    CVE-2026-120292, CVE-2026-120285, CVE-2026-120718 - CVSS 9.3 Critical).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "F5 BIG-IP TMOS & APM Version Compliance Audit (CVE-2026-123637)",
            "description": (
                "Passive version compliance check for F5 BIG-IP (17.1.x < 17.1.3.6, 17.5.x < 17.5.1.10, "
                "21.1.x < 21.1.0.2) against CVE-2026-123637, CVE-2026-120722, CVE-2026-121805, "
                "CVE-2026-116953, CVE-2026-120292, CVE-2026-120285, and CVE-2026-120718 (CVSS 9.3)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-123637",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_BIGIP_PORTS.copy()
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
                    or "big-ip" in s_name
                    or "bigip" in s_name
                    or "f5" in s_name
                    or "http" in s_name
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
        path: str = "/tmui/login.jsp",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-123637)",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
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
            logger.debug(f"F5 BIG-IP HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/tmui/login.jsp", "BIG-IP TMUI Configuration Utility"),
            ("/mgmt/tm/sys/version", "BIG-IP iControl REST Version Metadata"),
            ("/", "HTTP Root Banner / Headers"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            if "big-ip" in combined.lower() or "bigip" in combined.lower() or "f5" in combined.lower():
                ver_info = parse_bigip_version(combined)
                if ver_info:
                    v1, v2, v3, v4, ver_str = ver_info
                    is_vuln, reason = is_bigip_version_vulnerable(v1, v2, v3, v4, ver_str)
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
                    f"- [{port_label}] F5 BIG-IP {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] F5 BIG-IP {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-123637 & related advisories affected F5 BIG-IP appliance detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-123637 & Related Advisories - CVSS 9.3):\n"
                f"The target host {target_ip} exposes an unpatched F5 BIG-IP appliance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-123637 (CVSS 9.3): BIG-IP APM per-request policy TMM termination and potential RCE.\n"
                f"- CVE-2026-120722 (CVSS 9.3): BIG-IP DNS::scrape iRule TMM termination and potential RCE.\n"
                f"- CVE-2026-121805 (CVSS 9.3): BIG-IP PEM::subscriber iRule TMM termination and potential RCE.\n"
                f"- CVE-2026-116953 (CVSS 9.3): BIG-IP GENERICMESSAGE::route iRule TMM termination and potential RCE.\n"
                f"- CVE-2026-120292 (CVSS 9.3): BIG-IP MR::message route iRule TMM termination and potential RCE.\n"
                f"- CVE-2026-120285 (CVSS 9.3): BIG-IP PSC::ip_address iRule TMM termination and potential RCE.\n"
                f"- CVE-2026-120718 (CVSS 9.2): BIG-IP iControl REST token expiration defect.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade F5 BIG-IP to 17.1.3.6+ (17.1.x), 17.5.1.10+ (17.5.x), or 21.1.0.2+ (21.1.x).\n"
                f"2. Restrict management access to TMUI and iControl REST to trusted administrative networks."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: F5 BIG-IP instance on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected F5 BIG-IP services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for F5 BIG-IP (CVE-2026-123637 & related advisories)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_BIGIP_PORTS,
        help="Ports to inspect (default: 443 8443 4353 80)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = F5BigIpAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an F5 BIG-IP version affected by CVE-2026-123637.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
