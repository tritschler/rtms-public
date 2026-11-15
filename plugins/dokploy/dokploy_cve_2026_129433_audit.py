"""
dokploy_cve_2026_129433_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and version verification for
Dokploy PaaS instances to check patch compliance against:
  - CVE-2026-129433 (CVSS 9.4, affected: < 0.31.1): OS command injection
    vulnerability in getComposeContainerCommand() via the serviceName parameter.

Fixed in: Dokploy 0.31.1+.

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

DEFAULT_WEB_PORTS = [80, 443, 3000, 8080, 8443]
SSL_PORTS = {443, 8443}
MIN_PATCHED_VERSION = (0, 31, 1)


def parse_dokploy_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Dokploy semantic version (major, minor, patch, raw_str) from:
      - HTTP headers or status strings: 'Dokploy/0.31.0', 'Dokploy v0.30.2'
      - JSON or tRPC metadata: '"dokploy_version": "0.31.0"', '"version": "v0.30.5"'
    """
    if not text:
        return None

    patterns = [
        r"Dokploy[/\s]+v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?",
        r"[\"'](?:dokploy_)?version[\"']\s*:\s*[\"']v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?[\"']",
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


def is_dokploy_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Dokploy version tuple (major, minor, patch) is affected by:
      - CVE-2026-129433 (< 0.31.1)
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if ver_tuple < MIN_PATCHED_VERSION:
        return True, (
            f"Dokploy {ver_str} is affected by CVE-2026-129433 "
            f"(affected: < 0.31.1; requires upgrade to Dokploy >= 0.31.1)."
        )

    return False, (
        f"Dokploy {ver_str} is patched against CVE-2026-129433 "
        f"(running >= 0.31.1)."
    )


class DokployAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Dokploy PaaS Version Compliance Audit (CVE-2026-129433).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Dokploy PaaS Version Compliance Audit (CVE-2026-129433)",
            "description": (
                "Passive version compliance check for Dokploy < 0.31.1 "
                "(CVE-2026-129433 — CVSS 9.4)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-129433",
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
                    or "dokploy" in s_name
                    or "ssl" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 3000, 8080, 8443):
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-129433)",
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
            ("/", "HTTP Root Banner"),
            ("/api/trpc/settings.getDokployVersion", "Dokploy tRPC Version Endpoint"),
        ]

        dokploy_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")
            combined = f"{server_hdr}\n{powered_by}\n{headers}\n{body}"
            combined_lower = combined.lower()

            if "dokploy" in combined_lower or (path != "/" and probe.get("status_code") == 200 and "version" in combined_lower):
                dokploy_detected = True
                detected_source = f"{source_label} ({path})"

                ver_info = parse_dokploy_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_dokploy_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if dokploy_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Dokploy platform is active on this endpoint, but its exact version string is concealed. "
                    "Verify that Dokploy is updated to >= 0.31.1."
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
                    f"- [{port_label}] Dokploy {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Dokploy {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated Dokploy version detected on {target_ip} "
                f"(CVE-2026-129433).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (Dokploy < 0.31.1 - CVSS 9.4):\n"
                f"The target host {target_ip} runs an unpatched version of Dokploy.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-129433 (CVSS 9.4): OS command injection vulnerability in getComposeContainerCommand() "
                f"via the serviceName parameter in Dokploy before 0.31.1.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Dokploy to version 0.31.1 or later."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Dokploy active with concealed version metadata."
            details = (
                f"Dokploy detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Dokploy instances on {target_ip} are running patched versions (>= 0.31.1):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Dokploy services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Dokploy PaaS (CVE-2026-129433)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_WEB_PORTS,
        help="Ports to inspect (default: 80 443 3000 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = DokployAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Dokploy version affected by CVE-2026-129433.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes Dokploy services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
