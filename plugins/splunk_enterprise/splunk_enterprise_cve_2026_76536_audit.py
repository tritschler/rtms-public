"""
splunk_enterprise_cve_2026_76536_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS login page and REST metadata version verification
for Splunk Enterprise, Splunk SOAR, and Splunk Enterprise Security against the
November 2026 Multi-CVE Security Advisories (5 CVEs):
  - CVE-2026-76536 (CVSS 9.4 Critical): Unauthenticated cluster configuration read/write via empty clustering shared secret in Splunk Enterprise.
  - CVE-2026-76535 (CVSS 9.1 Critical): Unauthenticated arbitrary SPL execution via RapidDiag empty shared secret in Splunk Enterprise.
  - CVE-2026-131253 (CVSS 9.9 Critical): Arbitrary code execution via App Wizard identifier validation flaw in Splunk SOAR.
  - CVE-2026-131287 (CVSS 9.6 Critical): Arbitrary playbook code execution via deleted repository name reuse in Splunk SOAR.
  - CVE-2026-131202 (CVSS 9.1 Critical): Arbitrary code execution via lookup upload and Configuration Checker in Splunk Enterprise Security.

Affected Versions:
  - Splunk Enterprise: < 9.4.17, 10.0.x < 10.0.12, 10.2.x < 10.2.9, 10.4.x < 10.4.5, 10.6.x < 10.6.1
  - Splunk SOAR: < 8.8.0
  - Splunk Enterprise Security: < 8.7.0

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
                return self.format_result("Skipped", details="Requirements not met (no target Splunk ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_SPLUNK_PORTS = [8000, 8089, 443, 8443, 80, 8080]
SSL_PORTS = {443, 8443, 8089}


def parse_splunk_version(text: str) -> Optional[Tuple[str, int, int, int, str]]:
    """
    Extracts Splunk product and version tuple (product, major, minor, patch, raw_str)
    from Splunk Web login pages, REST /services/server/info, or SOAR metadata.

    Products returned: 'enterprise', 'soar', or 'enterprise_security'.
    """
    if not text:
        return None

    soar_match = re.search(
        r"Splunk\s+SOAR[\s:/v\"'-]+([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b",
        text,
        re.IGNORECASE,
    )
    if soar_match:
        major = int(soar_match.group(1))
        minor = int(soar_match.group(2))
        patch = int(soar_match.group(3)) if soar_match.group(3) is not None else 0
        raw_str = f"{major}.{minor}.{patch}"
        return "soar", major, minor, patch, raw_str

    es_match = re.search(
        r"Splunk\s+Enterprise\s+Security[\s:/v\"'-]+([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b",
        text,
        re.IGNORECASE,
    )
    if es_match:
        major = int(es_match.group(1))
        minor = int(es_match.group(2))
        patch = int(es_match.group(3)) if es_match.group(3) is not None else 0
        raw_str = f"{major}.{minor}.{patch}"
        return "enterprise_security", major, minor, patch, raw_str

    ent_patterns = [
        r"Splunk(?:\s+Enterprise)?[\s:/v\"'-]+([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})\b",
        r'"version"\s*:\s*"([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})"',
        r'<s:key\s+name="version">\s*([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})\s*</s:key>',
    ]
    if "splunk" in text.lower():
        for pat in ent_patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                patch = int(match.group(3))
                raw_str = f"{major}.{minor}.{patch}"
                return "enterprise", major, minor, patch, raw_str

    return None


def is_splunk_version_vulnerable(
    major: int,
    minor: int,
    patch: int,
    raw_str: str = "",
    product: str = "enterprise",
) -> Tuple[bool, str]:
    """
    Evaluates whether a Splunk Enterprise, Splunk SOAR, or Splunk Enterprise Security
    version is affected by CVE-2026-76536, CVE-2026-76535, CVE-2026-131253,
    CVE-2026-131287, or CVE-2026-131202.
    """
    ver = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"
    prod_norm = (product or "enterprise").lower()

    if prod_norm == "soar":
        if ver < (8, 8, 0):
            return True, (
                f"Splunk SOAR {ver_display} is prior to 8.8.0 and is affected by "
                f"CVE-2026-131253 (CVSS 9.9) and CVE-2026-131287 (CVSS 9.6)."
            )
        return False, f"Splunk SOAR {ver_display} is patched (>= 8.8.0) against CVE-2026-131253 and CVE-2026-131287."

    if prod_norm == "enterprise_security":
        if ver < (8, 7, 0):
            return True, (
                f"Splunk Enterprise Security {ver_display} is prior to 8.7.0 and is affected by "
                f"CVE-2026-131202 (CVSS 9.1)."
            )
        return False, f"Splunk Enterprise Security {ver_display} is patched (>= 8.7.0) against CVE-2026-131202."

    # Default: Splunk Enterprise
    if ver < (9, 4, 17):
        return True, (
            f"Splunk Enterprise {ver_display} is prior to 9.4.17 and is affected by "
            f"CVE-2026-76536 (CVSS 9.4) and CVE-2026-76535 (CVSS 9.1)."
        )

    if (9, 4, 17) <= ver < (10, 0, 0):
        return False, (
            f"Splunk Enterprise {ver_display} is patched in the 9.4.x branch (>= 9.4.17) against "
            f"CVE-2026-76536 and CVE-2026-76535."
        )

    if (10, 0, 0) <= ver < (10, 0, 12):
        return True, (
            f"Splunk Enterprise {ver_display} is in the 10.0.x branch prior to 10.0.12 and is affected by "
            f"CVE-2026-76536 (CVSS 9.4) and CVE-2026-76535 (CVSS 9.1)."
        )

    if (10, 0, 12) <= ver < (10, 2, 0):
        return False, (
            f"Splunk Enterprise {ver_display} is patched in the 10.0.x branch (>= 10.0.12) against "
            f"CVE-2026-76536 and CVE-2026-76535."
        )

    if (10, 2, 0) <= ver < (10, 2, 9):
        return True, (
            f"Splunk Enterprise {ver_display} is in the 10.2.x branch prior to 10.2.9 and is affected by "
            f"CVE-2026-76536 (CVSS 9.4) and CVE-2026-76535 (CVSS 9.1)."
        )

    if (10, 2, 9) <= ver < (10, 4, 0):
        return False, (
            f"Splunk Enterprise {ver_display} is patched in the 10.2.x branch (>= 10.2.9) against "
            f"CVE-2026-76536 and CVE-2026-76535."
        )

    if (10, 4, 0) <= ver < (10, 4, 5):
        return True, (
            f"Splunk Enterprise {ver_display} is in the 10.4.x branch prior to 10.4.5 and is affected by "
            f"CVE-2026-76536 (CVSS 9.4) and CVE-2026-76535 (CVSS 9.1)."
        )

    if (10, 4, 5) <= ver < (10, 6, 0):
        return False, (
            f"Splunk Enterprise {ver_display} is patched in the 10.4.x branch (>= 10.4.5) against "
            f"CVE-2026-76536 and CVE-2026-76535."
        )

    if (10, 6, 0) <= ver < (10, 6, 1):
        return True, (
            f"Splunk Enterprise {ver_display} is in the 10.6.x branch prior to 10.6.1 and is affected by "
            f"CVE-2026-76535 (CVSS 9.1)."
        )

    return False, (
        f"Splunk Enterprise {ver_display} is patched (>= 10.6.1) against CVE-2026-76536 and CVE-2026-76535."
    )


class SplunkEnterpriseAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Splunk Enterprise, SOAR & Enterprise Security Compliance Audit
    (CVE-2026-76536, CVE-2026-76535, CVE-2026-131253, CVE-2026-131287, CVE-2026-131202).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Splunk Enterprise & SOAR Multi-CVE Version Compliance Audit (CVE-2026-76536)",
            "description": (
                "Passive version compliance check for Splunk Enterprise (< 9.4.17, 10.0 < 10.0.12, "
                "10.2 < 10.2.9, 10.4 < 10.4.5, 10.6 < 10.6.1), Splunk SOAR (< 8.8.0), and "
                "Splunk Enterprise Security (< 8.7.0) against CVE-2026-76536, CVE-2026-76535, "
                "CVE-2026-131253, CVE-2026-131287, and CVE-2026-131202."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-76536",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_SPLUNK_PORTS.copy()
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

                if port in self.target_ports or "splunk" in s_name or "http" in s_name:
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
        path: str = "/en-US/account/login",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-76536)",
                "Accept": "text/html,application/xhtml+xml,application/json,application/xml,*/*",
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
            logger.debug(f"Splunk HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/en-US/account/login", "Splunk Web Login Page"),
            ("/services/server/info", "Splunkd REST Server Info Endpoint"),
            ("/login", "Splunk SOAR Login Page"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            if "splunk" in combined.lower():
                ver_info = parse_splunk_version(combined)
                if ver_info:
                    prod, major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_splunk_version_vulnerable(major, minor, patch, ver_str, product=prod)
                    return {
                        "port": port,
                        "service_detected": True,
                        "product": prod,
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
                    f"- [{port_label}] Splunk ({result.get('version')}) detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Splunk ({result.get('version')}) detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-76536 & related Splunk advisories: unpatched Splunk instance detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-76536 & Related Splunk Advisories - CVSS 9.1 to 9.9):\n"
                f"The target host {target_ip} exposes an unpatched Splunk instance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-76536 (CVSS 9.4): Unauthenticated cluster configuration exposure/modification via empty shared secret in Splunk Enterprise.\n"
                f"- CVE-2026-76535 (CVSS 9.1): Unauthenticated arbitrary SPL execution via RapidDiag empty shared secret in Splunk Enterprise.\n"
                f"- CVE-2026-131253 (CVSS 9.9): Arbitrary code execution via App Wizard in Splunk SOAR (< 8.8.0).\n"
                f"- CVE-2026-131287 (CVSS 9.6): Arbitrary playbook code execution via deleted repository name reuse in Splunk SOAR (< 8.8.0).\n"
                f"- CVE-2026-131202 (CVSS 9.1): Arbitrary code execution via lookup upload & Configuration Checker in Splunk Enterprise Security (< 8.7.0).\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Splunk Enterprise to 9.4.17+, 10.0.12+, 10.2.9+, 10.4.5+, or 10.6.1+.\n"
                f"2. Upgrade Splunk SOAR to 8.8.0+ and Splunk Enterprise Security to 8.7.0+."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Splunk instance on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Splunk Enterprise or SOAR services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Splunk Enterprise & SOAR (CVE-2026-76536 & related CVEs)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_SPLUNK_PORTS,
        help="Ports to inspect (default: 8000 8089 443 8443 80 8080)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = SplunkEnterpriseAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Splunk version affected by CVE-2026-76536.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
