"""
phpmyfaq_cve_2026_130369_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and version verification for
phpMyFAQ instances to check patch compliance against:
  - CVE-2026-130369 (CVSS v4.0: 9.2 Critical, affected: 4.1.9 - < 4.1.12 and
    4.2.0-alpha - < 4.2.0-RC.2): Multisite authorization bypass via shared
    PHP session store on WebAuthn passkey management.
  - CVE-2026-130371 (CVSS v4.0: 9.2 Critical, affected: < 4.1.12 and
    4.2.0-alpha - < 4.2.0-RC.2): Authentication bypass in the web installer
    during 3.x upgrade workflows.

Fixed in: phpMyFAQ 4.1.12+ and 4.2.0-RC.2+ (4.2.0+).

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

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443]
SSL_PORTS = {443, 8443}


def parse_phpmyfaq_version(text: str) -> Optional[Tuple[int, int, int, str, str]]:
    """
    Extracts phpMyFAQ semantic version (major, minor, patch, prerelease, raw_str) from:
      - HTML meta / footer: 'phpMyFAQ 4.1.10', 'phpMyFAQ 4.2.0-RC.1'
      - REST API version JSON: '{"version": "4.1.11"}'
    """
    if not text:
        return None

    patterns = [
        r"phpMyFAQ[/\s\-:v]+([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([a-zA-Z0-9.]+))?",
        r"[\"']version[\"']\s*:\s*[\"']v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([a-zA-Z0-9.]+))?[\"']",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            pre = (match.group(4) or "").strip()
            raw_str = f"{major}.{minor}.{patch}-{pre}" if pre else f"{major}.{minor}.{patch}"
            return major, minor, patch, pre, raw_str

    return None


def _is_4_2_0_prerelease_vulnerable(pre: str) -> bool:
    if not pre:
        return False
    pre_lower = pre.lower()
    if pre_lower.startswith("alpha") or pre_lower.startswith("beta"):
        return True
    rc_match = re.match(r"^rc(?:\.?([0-9]+))?$", pre_lower)
    if rc_match:
        rc_num = int(rc_match.group(1)) if rc_match.group(1) is not None else 1
        return rc_num < 2
    return False


def is_phpmyfaq_version_vulnerable(
    major: int, minor: int, patch: int, prerelease: str = "", raw_str: str = ""
) -> Tuple[bool, str]:
    """
    Evaluates whether a phpMyFAQ version is affected by:
      - CVE-2026-130371 (< 4.1.12 or 4.2.0-alpha before 4.2.0-RC.2)
      - CVE-2026-130369 (4.1.9 before 4.1.12 or 4.2.0-alpha before 4.2.0-RC.2)
    """
    ver_str = raw_str or (f"{major}.{minor}.{patch}-{prerelease}" if prerelease else f"{major}.{minor}.{patch}")
    ver_tuple = (major, minor, patch)

    if ver_tuple < (4, 1, 12):
        if (major, minor) == (4, 1) and patch >= 9:
            cves = "CVE-2026-130369 and CVE-2026-130371"
        else:
            cves = "CVE-2026-130371"
        return True, (
            f"phpMyFAQ {ver_str} is affected by {cves} "
            f"(affected: < 4.1.12; requires upgrade to phpMyFAQ >= 4.1.12)."
        )

    if ver_tuple == (4, 2, 0) and _is_4_2_0_prerelease_vulnerable(prerelease):
        return True, (
            f"phpMyFAQ {ver_str} is affected by CVE-2026-130369 and CVE-2026-130371 "
            f"(affected: 4.2.0-alpha before 4.2.0-RC.2; requires upgrade to >= 4.2.0-RC.2)."
        )

    return False, (
        f"phpMyFAQ {ver_str} is patched against CVE-2026-130369 and CVE-2026-130371 "
        f"(running >= 4.1.12 / >= 4.2.0-RC.2)."
    )


class PhpMyFAQAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: phpMyFAQ Version Compliance Audit (CVE-2026-130369 / CVE-2026-130371).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "phpMyFAQ Version Compliance Audit (CVE-2026-130369 / CVE-2026-130371)",
            "description": (
                "Passive version compliance check for phpMyFAQ < 4.1.12 and 4.2.0-alpha < 4.2.0-RC.2 "
                "(CVE-2026-130369 / CVE-2026-130371 — CVSS 9.2)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-130369",
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
                    or "phpmyfaq" in s_name
                    or "ssl" in s_name
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-130369)",
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
            ("/api/v3.0/version", "phpMyFAQ REST API Version Endpoint"),
        ]

        phpmyfaq_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"
            combined_lower = combined.lower()

            if "phpmyfaq" in combined_lower or (path != "/" and probe.get("status_code") == 200 and "version" in combined_lower):
                phpmyfaq_detected = True
                detected_source = f"{source_label} ({path})"

                ver_info = parse_phpmyfaq_version(combined)
                if ver_info:
                    major, minor, patch, pre, ver_str = ver_info
                    is_vuln, reason = is_phpmyfaq_version_vulnerable(major, minor, patch, pre, ver_str)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if phpmyfaq_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "phpMyFAQ is active on this endpoint, but its exact version string is concealed. "
                    "Verify that phpMyFAQ is updated to >= 4.1.12 or >= 4.2.0-RC.2."
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
                    f"- [{port_label}] phpMyFAQ {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] phpMyFAQ {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"Outdated phpMyFAQ version detected on {target_ip} "
                f"(CVE-2026-130369 / CVE-2026-130371).\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (phpMyFAQ < 4.1.12 / < 4.2.0-RC.2 - CVSS 9.2):\n"
                f"The target host {target_ip} runs an unpatched version of phpMyFAQ.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-130369 (CVSS 9.2): Authorization bypass in multisite deployments via shared PHP "
                f"session store in phpMyFAQ 4.1.9 before 4.1.12 and 4.2.0-alpha before 4.2.0-RC.2.\n"
                f"- CVE-2026-130371 (CVSS 9.2): Authentication bypass in the web installer during 3.x upgrade "
                f"workflows in phpMyFAQ before 4.1.12 and 4.2.0-alpha before 4.2.0-RC.2.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade phpMyFAQ 4.1.x (or earlier) to version 4.1.12 or later.\n"
                f"2. Upgrade phpMyFAQ 4.2.0 pre-releases to version 4.2.0-RC.2 or later."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "phpMyFAQ active with concealed version metadata."
            details = (
                f"phpMyFAQ detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: phpMyFAQ instances on {target_ip} are running patched versions (>= 4.1.12 / >= 4.2.0-RC.2):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected phpMyFAQ services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for phpMyFAQ (CVE-2026-130369 / CVE-2026-130371)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_WEB_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = PhpMyFAQAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a phpMyFAQ version affected by CVE-2026-130369 / CVE-2026-130371.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes phpMyFAQ services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
