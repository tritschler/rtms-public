"""
sharepoint_cve_2026_120002_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS response header verification (`MicrosoftSharePointTeamServices`)
for on-premises Microsoft SharePoint Server deployments to check patch compliance against the
November 2026 Microsoft Patch Tuesday Critical SharePoint Advisories:
  - CVE-2026-120002 (CVSS 9.9 Critical): Incorrect authorization in Microsoft Office SharePoint
  - CVE-2026-80095 (CVSS 9.0 Critical): Improper neutralization of input (XSS) in Microsoft SharePoint
  - CVE-2026-109454 (CVSS 9.0 Critical): Improper neutralization of input (Spoofing) in Microsoft SharePoint

Affected Editions & Minimum Safe Builds (November 2026 Patch Tuesday):
  - SharePoint Server Subscription Edition: < 16.0.18526.20650
  - SharePoint Server 2019:                 < 16.0.10417.20075
  - SharePoint Server 2016:                 < 16.0.5580.1000
  - SharePoint Server 2013 / 2010 (15.0 / 14.0): End-of-Life (unpatched)

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
                return self.format_result("Skipped", details="Requirements not met (no target SharePoint HTTP/HTTPS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_SHAREPOINT_PORTS = [80, 443, 8080, 8443]
SSL_PORTS = {443, 8443, 9443}


def parse_sharepoint_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts Microsoft SharePoint 4-part build version (major, minor, build, revision, raw_str)
    from `MicrosoftSharePointTeamServices` headers or response metadata.
    Examples:
      - 'MicrosoftSharePointTeamServices: 16.0.0.10416' -> (16, 0, 10416, 0, '16.0.0.10416')
      - '16.0.18526.20400' -> (16, 0, 18526, 20400, '16.0.18526.20400')
      - '16.0.10417.20075' -> (16, 0, 10417, 20075, '16.0.10417.20075')
    """
    if not text:
        return None

    match = re.search(
        r"\b(1[456])\.0\.([0-9]+)\.([0-9]+)\b",
        text,
    )
    if not match:
        return None

    major = int(match.group(1))
    part3 = int(match.group(2))
    part4 = int(match.group(3))
    raw_str = match.group(0)

    # Handle `16.0.0.<build>` header notation used by some SharePoint 2016/2019 configurations
    if part3 == 0 and part4 >= 4000:
        build = part4
        revision = 0
    else:
        build = part3
        revision = part4

    return major, 0, build, revision, raw_str


def is_sharepoint_version_vulnerable(
    major: int, minor: int, build: int, revision: int
) -> Tuple[bool, str]:
    """
    Evaluates whether a Microsoft SharePoint build tuple is affected by
    CVE-2026-120002 (CVSS 9.9), CVE-2026-80095 (CVSS 9.0), and CVE-2026-109454 (CVSS 9.0).
    """
    ver_str = f"{major}.{minor}.{build}.{revision}"

    if major in (14, 15):
        edition = "SharePoint 2013" if major == 15 else "SharePoint 2010"
        return True, (
            f"{edition} ({ver_str}) is End-of-Life and unpatched against CVE-2026-120002 (CVSS 9.9)."
        )

    if major != 16:
        return False, f"Build {ver_str} is outside known on-premises SharePoint Server branches."

    # SharePoint Server 2016 (builds 4000 - 5999)
    if 4000 <= build < 6000:
        if (build, revision) < (5580, 1000):
            return True, (
                f"SharePoint Server 2016 build {ver_str} is prior to the November 2026 Security Update "
                f"(< 16.0.5580.1000) and is affected by CVE-2026-120002, CVE-2026-80095, and CVE-2026-109454."
            )
        return False, (
            f"SharePoint Server 2016 build {ver_str} meets or exceeds the November 2026 Security Update "
            f"(>= 16.0.5580.1000)."
        )

    # SharePoint Server 2019 (builds 10300 - 10999)
    if 10000 <= build < 11000:
        if (build, revision) < (10417, 20075):
            return True, (
                f"SharePoint Server 2019 build {ver_str} is prior to the November 2026 Security Update "
                f"(< 16.0.10417.20075) and is affected by CVE-2026-120002, CVE-2026-80095, and CVE-2026-109454."
            )
        return False, (
            f"SharePoint Server 2019 build {ver_str} meets or exceeds the November 2026 Security Update "
            f"(>= 16.0.10417.20075)."
        )

    # SharePoint Server Subscription Edition (builds 14000 - 19999)
    if 14000 <= build < 20000:
        if (build, revision) < (18526, 20650):
            return True, (
                f"SharePoint Server Subscription Edition build {ver_str} is prior to the November 2026 "
                f"Security Update (< 16.0.18526.20650) and is affected by CVE-2026-120002, CVE-2026-80095, and CVE-2026-109454."
            )
        return False, (
            f"SharePoint Server Subscription Edition build {ver_str} meets or exceeds the November 2026 "
            f"Security Update (>= 16.0.18526.20650)."
        )

    return False, f"SharePoint build {ver_str} is outside the affected on-premises build ranges."


class SharePointAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Microsoft SharePoint Server Compliance Audit (CVE-2026-120002).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Microsoft SharePoint Server Version Compliance Audit (CVE-2026-120002)",
            "description": (
                "Passive HTTP header version compliance check for Microsoft SharePoint Server "
                "against CVE-2026-120002 (CVSS 9.9), CVE-2026-80095 (CVSS 9.0), and CVE-2026-109454 (CVSS 9.0)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-120002",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_SHAREPOINT_PORTS.copy()
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
                    or "sharepoint" in s_name
                    or "iis" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 8080, 8443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-120002)",
                "Accept": "text/html,application/xhtml+xml,*/*",
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
            ("/", "SharePoint root HTTP response"),
            ("/_layouts/15/viewlsts.aspx", "SharePoint /_layouts/15/viewlsts.aspx"),
            ("/_vti_bin/spsdisco.aspx", "SharePoint /_vti_bin/spsdisco.aspx"),
        ]

        sp_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            sp_header = headers.get("microsoftsharepointteamservices", "")
            health_hdr = headers.get("x-sharepointhealthscore", "")
            sp_guid = headers.get("sprequestguid", "")

            if (
                sp_header
                or health_hdr
                or sp_guid
                or "microsoftsharepointteamservices" in body.lower()
                or "/_layouts/15/" in body.lower()
            ):
                sp_detected = True
                detected_source = (
                    f"{source_label} (MicrosoftSharePointTeamServices header)"
                    if sp_header
                    else source_label
                )

                combined = f"{sp_header}\n{body}"
                ver_info = parse_sharepoint_version(combined)
                if ver_info:
                    major, minor, build, revision, ver_str = ver_info
                    is_vuln, reason = is_sharepoint_version_vulnerable(major, minor, build, revision)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if sp_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Microsoft SharePoint Server detected, but the `MicrosoftSharePointTeamServices` "
                    "build header is suppressed. Verify November 2026 cumulative updates are applied."
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
                    f"- [{port_label}] SharePoint build {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] SharePoint build {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-120002 / CVE-2026-80095 / CVE-2026-109454 affected Microsoft SharePoint build detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-120002 - CVSS 9.9):\n"
                f"The target host {target_ip} runs an unpatched Microsoft SharePoint Server build.\n\n"
                f"Associated November 2026 Patch Tuesday SharePoint Advisories:\n"
                f"- CVE-2026-120002 (CVSS 9.9): Incorrect authorization privilege escalation\n"
                f"- CVE-2026-80095 (CVSS 9.0): Cross-Site Scripting (XSS) privilege escalation\n"
                f"- CVE-2026-109454 (CVSS 9.0): Cross-Site Scripting (Spoofing)\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Apply the November 2026 Microsoft SharePoint Server Security Update:\n"
                f"   - SharePoint Server Subscription Edition: >= 16.0.18526.20650\n"
                f"   - SharePoint Server 2019:                 >= 16.0.10417.20075\n"
                f"   - SharePoint Server 2016:                 >= 16.0.5580.1000\n"
                f"2. Run the SharePoint Products Configuration Wizard (`psconfig.exe`) on all farm servers after patching."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Microsoft SharePoint Server detected with concealed version header."
            details = (
                f"SharePoint HTTP service detected on {target_ip}, but build headers are suppressed:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Microsoft SharePoint Server on {target_ip} meets the November 2026 patch level:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Microsoft SharePoint Server HTTP services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Microsoft SharePoint Server (CVE-2026-120002)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_SHAREPOINT_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = SharePointAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} requires Microsoft SharePoint November 2026 Security Updates (CVE-2026-120002).\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} requires manual SharePoint build verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
