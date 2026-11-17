"""
arize_phoenix_cve_2026_53998_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and version verification for
Arize AI Phoenix observability instances to check patch compliance against:
  - CVE-2026-53998 (CVSS v3.1: 10.0 Critical, affected: >= 13.0.0, < 15.7.0):
    Attribute traversal in FStringTemplateFormatter via the applyChatTemplate
    GraphQL query in Arize AI Phoenix from 13.0.0 before 15.7.0.

Fixed in: Arize AI Phoenix 15.7.0+.

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
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/HTTPS services found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_WEB_PORTS = [6006, 80, 443, 8080, 8443]
SSL_PORTS = {443, 8443}


def parse_arize_phoenix_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Arize AI Phoenix semantic version (major, minor, patch, raw_str) from:
      - HTTP headers or banners: 'Arize-Phoenix/15.6.0', 'Phoenix/14.2.1'
      - HTML/JSON config metadata: '"phoenixVersion": "15.5.0"', '"phoenix_version": "15.7.0"'
    """
    if not text:
        return None

    patterns = [
        r"(?:Arize[\s\-]+)?Phoenix[/\s\-:v]+([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"[\"'](?:phoenix_?version|version)[\"']\s*:\s*[\"']v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?[\"']",
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


def is_arize_phoenix_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether an Arize AI Phoenix version tuple (major, minor, patch) is affected by:
      - CVE-2026-53998 (>= 13.0.0 and < 15.7.0)
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if (13, 0, 0) <= ver_tuple < (15, 7, 0):
        return True, (
            f"Arize AI Phoenix {ver_str} is affected by CVE-2026-53998 "
            f"(affected: >= 13.0.0, < 15.7.0; requires upgrade to Arize AI Phoenix >= 15.7.0)."
        )

    return False, (
        f"Arize AI Phoenix {ver_str} is not affected by CVE-2026-53998 "
        f"(patched in >= 15.7.0)."
    )


class ArizePhoenixAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Arize AI Phoenix Version Compliance Audit (CVE-2026-53998).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Arize AI Phoenix Version Compliance Audit (CVE-2026-53998)",
            "description": (
                "Passive version compliance check for Arize AI Phoenix >= 13.0.0, < 15.7.0 "
                "(CVE-2026-53998 — CVSS 10.0)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-53998",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_WEB_PORTS.copy()
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
                    or "web" in s_name
                    or "phoenix" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (6006, 80, 443, 8080, 8443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-53998)",
                "Accept": "text/html,application/json,text/plain,*/*",
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
            ("/", "HTTP Root Page"),
            ("/arize_phoenix_version", "Phoenix Version Endpoint"),
        ]

        phoenix_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"
            combined_lower = combined.lower()

            if "arize" in combined_lower or "phoenixversion" in combined_lower or "arize-phoenix" in combined_lower:
                phoenix_detected = True
                detected_source = f"{source_label} ({path})"

                ver_info = parse_arize_phoenix_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_arize_phoenix_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if phoenix_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Arize AI Phoenix is active on this endpoint, but its exact version string is concealed. "
                    "Verify that Arize AI Phoenix is updated to >= 15.7.0."
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
                    f"- [{port_label}] Arize AI Phoenix {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Arize AI Phoenix {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated Arize AI Phoenix version detected on {target_ip} "
                f"(CVE-2026-53998).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (Arize AI Phoenix 13.0.0 - < 15.7.0 - CVSS 10.0):\n"
                f"The target host {target_ip} runs an unpatched version of Arize AI Phoenix.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-53998 (CVSS 10.0): Attribute traversal in FStringTemplateFormatter via the "
                f"applyChatTemplate GraphQL query in Arize AI Phoenix from 13.0.0 before 15.7.0.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Arize AI Phoenix to version 15.7.0 or later."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Arize AI Phoenix active with concealed version metadata."
            details = (
                f"Arize AI Phoenix detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Arize AI Phoenix instances on {target_ip} are running patched versions (>= 15.7.0):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Arize AI Phoenix services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Arize AI Phoenix (CVE-2026-53998)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_WEB_PORTS,
        help="Ports to inspect (default: 6006 80 443 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = ArizePhoenixAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an Arize AI Phoenix version affected by CVE-2026-53998.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes Arize AI Phoenix services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
