"""
synology_dsm_cve_2026_76954_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS web desktop metadata and public API version
verification for Synology DiskStation Manager (DSM) NAS appliances to check patch
compliance against:
  - CVE-2026-76954 (CVSS 9.8 Critical): Improper neutralization of special elements
    used in an SQL command (SQL Injection) in the Synology DSM Auth API.

Affected Versions:
  - Synology DSM < 7.2.1-69057-13 (Fixed in 7.2.1-69057 Update 13+)
  - Synology DSM 7.2.2 < 7.2.2-72806-10 (Fixed in 7.2.2-72806 Update 10+)
  - Synology DSM 7.3.x < 7.3.2-86009-5 (Fixed in 7.3.2-86009 Update 5+)
  - Synology DSM 7.4.x < 7.4.1-90080-1 (Fixed in 7.4.1-90080 Update 1+)

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
                return self.format_result("Skipped", details="Requirements not met (no target Synology DSM ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_DSM_PORTS = [5000, 5001, 443, 80]
SSL_PORTS = {443, 5001, 8443}


def parse_synology_dsm_version(text: str) -> Optional[Tuple[int, int, int, int, int, str]]:
    """
    Extracts Synology DSM version tuple (major, minor, micro, build, update_num, raw_str)
    from web portal HTML, static asset query strings, or API metadata.
    Examples:
      - '7.2.1-69057-12' -> (7, 2, 1, 69057, 12, '7.2.1-69057-12')
      - 'DSM 7.2.2-72806 Update 9' -> (7, 2, 2, 72806, 9, '7.2.2-72806-9')
      - 'v=7.4.1-90080' -> (7, 4, 1, 90080, 0, '7.4.1-90080-0')
    """
    if not text:
        return None

    patterns = [
        r"\b([67])\.([0-9]+)\.([0-9]+)-([0-9]{5,6})(?:-(?:Update\s*)?([0-9]+)|\s+Update\s+([0-9]+))?\b",
        r"(?:dsm_version|version_string|fullversion)\s*[:=]\s*[\"']?v?([67])\.([0-9]+)\.([0-9]+)-([0-9]{5,6})(?:-([0-9]+))?",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            micro = int(match.group(3))
            build = int(match.group(4))
            upd_str = match.group(5) or (match.group(6) if match.lastindex and match.lastindex >= 6 else None)
            update_num = int(upd_str) if upd_str is not None else 0
            ver_str = f"{major}.{minor}.{micro}-{build}-{update_num}"
            return major, minor, micro, build, update_num, ver_str

    return None


def is_synology_dsm_version_vulnerable(
    major: int, minor: int, micro: int, build: int, update_num: int
) -> Tuple[bool, str]:
    """
    Evaluates whether a Synology DSM release tuple is affected by CVE-2026-76954 (CVSS 9.8).
      - < 7.2.1-69057-13: Vulnerable
      - 7.2.2 < 7.2.2-72806-10: Vulnerable
      - 7.3.x < 7.3.2-86009-5: Vulnerable
      - 7.4.x < 7.4.1-90080-1: Vulnerable
    """
    ver_str = f"{major}.{minor}.{micro}-{build}-{update_num}"

    if (major, minor, micro) < (7, 2, 1):
        return True, (
            f"Synology DSM {ver_str} is earlier than the minimum patched branch 7.2.1-69057-13 "
            f"for CVE-2026-76954."
        )

    if (major, minor, micro) == (7, 2, 1):
        if (build, update_num) < (69057, 13):
            return True, (
                f"Synology DSM {ver_str} is prior to 7.2.1-69057-13 and is affected by CVE-2026-76954."
            )
        return False, f"Synology DSM {ver_str} is patched (>= 7.2.1-69057-13) against CVE-2026-76954."

    if (major, minor, micro) == (7, 2, 2):
        if (build, update_num) < (72806, 10):
            return True, (
                f"Synology DSM {ver_str} is prior to 7.2.2-72806-10 and is affected by CVE-2026-76954."
            )
        return False, f"Synology DSM {ver_str} is patched (>= 7.2.2-72806-10) against CVE-2026-76954."

    if (major, minor) == (7, 3):
        if (micro, build, update_num) < (2, 86009, 5):
            return True, (
                f"Synology DSM {ver_str} is prior to 7.3.2-86009-5 and is affected by CVE-2026-76954."
            )
        return False, f"Synology DSM {ver_str} is patched (>= 7.3.2-86009-5) against CVE-2026-76954."

    if (major, minor) == (7, 4):
        if (micro, build, update_num) < (1, 90080, 1):
            return True, (
                f"Synology DSM {ver_str} is prior to 7.4.1-90080-1 and is affected by CVE-2026-76954."
            )
        return False, f"Synology DSM {ver_str} is patched (>= 7.4.1-90080-1) against CVE-2026-76954."

    return False, f"Synology DSM {ver_str} is outside the affected branches for CVE-2026-76954."


class SynologyDSMAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Synology DiskStation Manager (DSM) Compliance Audit (CVE-2026-76954).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Synology DiskStation Manager (DSM) Version Compliance Audit (CVE-2026-76954)",
            "description": (
                "Passive version compliance check for Synology DiskStation Manager (DSM) "
                "against CVE-2026-76954 (CVSS 9.8 Auth API SQL injection)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-76954",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_DSM_PORTS.copy()
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
                    or "synology" in s_name
                    or "dsm" in s_name
                    or "upnp" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 5000, 5001, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/webman/index.cgi",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-76954)",
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

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/webman/index.cgi", "Synology DSM /webman/index.cgi desktop portal"),
            (
                "/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth,SYNO.Core.System",
                "Synology DSM SYNO.API.Info metadata endpoint",
            ),
            ("/", "Synology DSM HTTP root"),
        ]

        dsm_detected = False
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
                "synology" in combined_lower
                or "diskstation" in combined_lower
                or "syno.api.auth" in combined_lower
                or "webman/index.cgi" in combined_lower
                or "syno_SDS" in combined
            ):
                dsm_detected = True
                detected_source = source_label

                ver_info = parse_synology_dsm_version(combined)
                if ver_info:
                    major, minor, micro, build, upd, ver_str = ver_info
                    is_vuln, reason = is_synology_dsm_version_vulnerable(major, minor, micro, build, upd)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if dsm_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Synology DSM web interface or API is active, but the exact build/update version "
                    "is concealed in unauthenticated responses. Verify DSM >= 7.2.1-69057-13 / 7.2.2-72806-10 / "
                    "7.3.2-86009-5 / 7.4.1-90080-1."
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
                    f"- [{port_label}] Synology DSM {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Synology DSM {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-76954 affected Synology DiskStation Manager (DSM) version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-76954 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an affected Synology DiskStation Manager (DSM) build.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-76954 (CVSS 9.8): Improper neutralization of special elements used in an SQL command "
                f"in the Synology DSM Auth API.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Update Synology DSM to 7.2.1-69057-13+, 7.2.2-72806-10+, 7.3.2-86009-5+, or 7.4.1-90080-1+.\n"
                f"2. Restrict external access to DSM management ports (5000/TCP and 5001/TCP) via firewall rules."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Synology DSM service detected (exact build/update version concealed)."
            details = (
                f"Synology DSM service detected on {target_ip}; manual build verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Synology DSM instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Synology DSM services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Synology DiskStation Manager (CVE-2026-76954)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_DSM_PORTS,
        help="Ports to inspect (default: 5000 5001 443 80)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = SynologyDSMAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Synology DSM build affected by CVE-2026-76954.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes Synology DSM services requiring build verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
