"""
redhat_quay_cve_2026_110697_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS discovery API, registry header, and web UI
metadata verification for Red Hat Quay / Project Quay container registries to check
patch compliance against:
  - CVE-2026-110697 (CVSS 9.9 Critical): Unescaped SQL LIKE wildcard metacharacters
    in Quay robot account listing allowing cross-tenant robot token disclosure.
  - CVE-2026-123710 (CVSS 9.8 Critical): Unrestricted service key rotation endpoint
    allowing unauthenticated signing key registration in Red Hat Quay.

Affected Versions & Minimum Patched Releases:
  - Red Hat Quay 3.18.x < 3.18.2 (Fixed in 3.18.2+)
  - Red Hat Quay 3.17.x < 3.17.3 (Fixed in 3.17.3+)
  - Red Hat Quay 3.16.x < 3.16.4 (Fixed in 3.16.4+)
  - Red Hat Quay 3.15.x < 3.15.5 (Fixed in 3.15.5+)
  - Red Hat Quay 3.14.x < 3.14.6 (Fixed in 3.14.6+)
  - Red Hat Quay 3.13.x < 3.13.8 (Fixed in 3.13.8+)
  - Red Hat Quay 3.12.x < 3.12.11 (Fixed in 3.12.11+)
  - Red Hat Quay < 3.12.0: End-of-Support (Vulnerable)

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
                return self.format_result("Skipped", details="Requirements not met (no target Red Hat Quay ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_QUAY_PORTS = [443, 8443, 8080, 80]
SSL_PORTS = {443, 8443, 9443}

QUAY_MIN_PATCHED_BY_MINOR: Dict[int, int] = {
    12: 11,
    13: 8,
    14: 6,
    15: 5,
    16: 4,
    17: 3,
    18: 2,
}


def parse_quay_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Red Hat Quay version tuple (major, minor, patch, raw_version_str)
    from HTTP headers, `/api/v1/discovery`, or web UI footer/script metadata.
    Examples:
      - 'Red Hat Quay v3.16.2' -> (3, 16, 2, '3.16.2')
      - '"version": "v3.18.1"' -> (3, 18, 1, '3.18.1')
      - 'quay_version = "3.14.5"' -> (3, 14, 5, '3.14.5')
    """
    if not text:
        return None

    patterns = [
        r"(?:Red\s+Hat\s+)?Quay\s+v?(3)\.([0-9]+)\.([0-9]+)",
        r"(?:quay_version|QUAY_VERSION|registry_version|\"version\")\s*[:=]\s*[\"']?v?(3)\.([0-9]+)\.([0-9]+)",
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


def is_quay_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Red Hat Quay version (major, minor, patch) is affected by
    CVE-2026-110697 (CVSS 9.9) and CVE-2026-123710 (CVSS 9.8).
    """
    ver_str = f"{major}.{minor}.{patch}"

    if major < 3:
        return True, (
            f"Red Hat Quay {ver_str} is End-of-Support and unpatched against "
            f"CVE-2026-110697 and CVE-2026-123710."
        )

    if major == 3:
        if minor < 12:
            return True, (
                f"Red Hat Quay {ver_str} (< 3.12.11) is End-of-Support and affected by "
                f"CVE-2026-110697 and CVE-2026-123710."
            )
        if minor in QUAY_MIN_PATCHED_BY_MINOR:
            min_patch = QUAY_MIN_PATCHED_BY_MINOR[minor]
            if patch < min_patch:
                return True, (
                    f"Red Hat Quay {ver_str} is prior to 3.{minor}.{min_patch} and is affected by "
                    f"CVE-2026-110697 and CVE-2026-123710."
                )
            return False, (
                f"Red Hat Quay {ver_str} is patched (>= 3.{minor}.{min_patch}) against "
                f"CVE-2026-110697 and CVE-2026-123710."
            )

    return False, f"Red Hat Quay {ver_str} is outside the affected 3.12–3.18 branches."


class RedHatQuayAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Red Hat Quay Version Compliance Audit
    (CVE-2026-110697, CVE-2026-123710).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Red Hat Quay Version Compliance Audit (CVE-2026-110697)",
            "description": (
                "Passive version compliance check for Red Hat Quay container registries "
                "against CVE-2026-110697 (CVSS 9.9) and CVE-2026-123710 (CVSS 9.8)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-110697",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_QUAY_PORTS.copy()
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
                    or "quay" in s_name
                    or "docker" in s_name
                    or "registry" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 5000, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/api/v1/discovery",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-110697)",
                "Accept": "application/json,text/html,*/*",
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
            ("/api/v1/discovery", "Red Hat Quay /api/v1/discovery endpoint"),
            ("/signin", "Red Hat Quay /signin web portal"),
            ("/v2/", "Red Hat Quay OCI /v2/ registry endpoint"),
        ]

        quay_detected = False
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
                "red hat quay" in combined_lower
                or "project quay" in combined_lower
                or "quay.io" in combined_lower
                or "quay_version" in combined_lower
                or ("docker-distribution-api-version" in combined_lower and "quay" in combined_lower)
            ):
                quay_detected = True
                detected_source = source_label

                ver_info = parse_quay_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_quay_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if quay_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "Red Hat Quay registry service is active, but the exact release version "
                    "is concealed in unauthenticated responses. Verify Quay >= 3.12.11 / 3.13.8 / "
                    "3.14.6 / 3.15.5 / 3.16.4 / 3.17.3 / 3.18.2."
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
                    f"- [{port_label}] Red Hat Quay {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Red Hat Quay {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-110697 / CVE-2026-123710 affected Red Hat Quay version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-110697 - CVSS 9.9 / CVE-2026-123710 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an affected Red Hat Quay container registry release.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-110697 (CVSS 9.9): Unescaped SQL LIKE wildcard characters in robot account listing.\n"
                f"- CVE-2026-123710 (CVSS 9.8): Unrestricted service key rotation endpoint registration.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Red Hat Quay to 3.12.11+, 3.13.8+, 3.14.6+, 3.15.5+, 3.16.4+, 3.17.3+, or 3.18.2+.\n"
                f"2. Audit existing service keys and robot account tokens across namespaces."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Red Hat Quay service detected (exact release version concealed)."
            details = (
                f"Red Hat Quay registry detected on {target_ip}; manual version verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Red Hat Quay instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Red Hat Quay services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Red Hat Quay (CVE-2026-110697 / CVE-2026-123710)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_QUAY_PORTS,
        help="Ports to inspect (default: 443 8443 8080 80)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = RedHatQuayAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Red Hat Quay version affected by CVE-2026-110697 / CVE-2026-123710.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes Red Hat Quay services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
