"""
gitlab_cve_2026_110264_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for GitLab Community
Edition (CE) and Enterprise Edition (EE) instances to check patch compliance against:
  - CVE-2026-110264 (CVSS 10.0 Critical): Unauthenticated remote code execution via
    integer overflow when compiling specially crafted regular expressions.
  - CVE-2026-85706 (CVSS 10.0 Critical): Unauthenticated arbitrary file read due to
    improper path confinement in GitLab CE/EE.

Affected Versions:
  - GitLab CE/EE 7.0 through 18.11.12 (Fixed in 18.11.13+)
  - GitLab CE/EE 19.0.0 through 19.0.9 (Fixed in 19.0.10+)
  - GitLab CE/EE 19.1.0 through 19.1.8 (Fixed in 19.1.9+)
  - GitLab CE/EE 19.2.0 through 19.2.8 (Fixed in 19.2.9+)
  - GitLab CE/EE 19.3.0 through 19.3.5 (Fixed in 19.3.6+)
  - GitLab CE/EE 19.4.0 through 19.4.2 (Fixed in 19.4.3+)
  - GitLab CE/EE 19.5.0 (Fixed in 19.5.1+)

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
                return self.format_result("Skipped", details="Requirements not met (no target GitLab HTTP/HTTPS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_GITLAB_PORTS = [80, 443, 8080, 8443]
SSL_PORTS = {443, 8443, 9443}


def parse_gitlab_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts GitLab version tuple (major, minor, patch, raw_version_str)
    from /api/v4/version JSON, /help, or gon.version metadata.
    """
    if not text:
        return None

    patterns = [
        r'"version"\s*:\s*"v?([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})(?:-[a-z0-9]+)?"',
        r'gon\.version\s*=\s*"v?([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})',
        r'GitLab\s+(?:Community|Enterprise)\s+Edition\s+([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})',
        r'data-version="v?([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})',
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


def is_gitlab_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a GitLab CE/EE version is affected by CVE-2026-110264 (CVSS 10.0)
    and CVE-2026-85706 (CVSS 10.0).
    """
    ver_str = f"{major}.{minor}.{patch}"

    if 7 <= major < 18:
        return True, (
            f"GitLab {ver_str} is prior to 18.11.13 and is vulnerable to CVE-2026-110264 (CVSS 10.0)."
        )

    if major == 18:
        if (minor, patch) < (11, 13):
            return True, (
                f"GitLab {ver_str} is prior to 18.11.13 and is affected by CVE-2026-110264 "
                f"and CVE-2026-85706 (upgrade to >= 18.11.13)."
            )
        return False, f"GitLab {ver_str} is patched (>= 18.11.13) against CVE-2026-110264 / CVE-2026-85706."

    if major == 19:
        thresholds = {
            0: 10,
            1: 9,
            2: 9,
            3: 6,
            4: 3,
            5: 1,
        }
        if minor in thresholds:
            min_safe = thresholds[minor]
            if patch < min_safe:
                return True, (
                    f"GitLab {ver_str} is in the affected 19.{minor}.x branch for CVE-2026-110264 "
                    f"(upgrade to >= 19.{minor}.{min_safe})."
                )
            return False, f"GitLab {ver_str} is patched (>= 19.{minor}.{min_safe}) against CVE-2026-110264."

    return False, f"GitLab {ver_str} is outside the affected ranges for CVE-2026-110264."


class GitLabAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: GitLab CE/EE Version Compliance Audit
    (CVE-2026-110264 & CVE-2026-85706 - CVSS 10.0).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "GitLab CE/EE Version Compliance Audit (CVE-2026-110264)",
            "description": (
                "Passive version compliance check for GitLab Community and Enterprise Edition (CE/EE) "
                "against CVE-2026-110264 (CVSS 10.0 RCE) and CVE-2026-85706 (CVSS 10.0 File Read)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-110264",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_GITLAB_PORTS.copy()
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
                    or "gitlab" in s_name
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
        path: str = "/users/sign_in",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-110264)",
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
            ("/api/v4/version", "GitLab REST API /api/v4/version"),
            ("/help", "GitLab /help documentation portal"),
            ("/users/sign_in", "GitLab /users/sign_in web portal"),
            ("/explore", "GitLab /explore public projects page"),
        ]

        gitlab_detected = False
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
                "_gitlab_session" in combined_lower
                or "x-gitlab-meta" in combined_lower
                or "gitlab community edition" in combined_lower
                or "gitlab enterprise edition" in combined_lower
                or "gon.default_issues_tracker" in combined_lower
                or 'content="gitlab"' in combined_lower
            ):
                gitlab_detected = True
                detected_source = source_label

                ver_info = parse_gitlab_version(combined)
                if ver_info:
                    major, minor, patch, ver_str = ver_info
                    is_vuln, reason = is_gitlab_version_vulnerable(major, minor, patch)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if gitlab_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "GitLab CE/EE instance is active, but exact version metadata requires authentication. "
                    "Verify GitLab version >= 18.11.13 / 19.0.10 / 19.1.9 / 19.2.9 / 19.3.6 / 19.4.3 / 19.5.1."
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
                    f"- [{port_label}] GitLab {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] GitLab {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-110264 / CVE-2026-85706 affected GitLab CE/EE version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-110264 & CVE-2026-85706 - CVSS 10.0):\n"
                f"The target host {target_ip} runs an unpatched GitLab CE/EE release.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-110264 (CVSS 10.0): Unauthenticated RCE via regex compilation integer overflow.\n"
                f"- CVE-2026-85706 (CVSS 10.0): Unauthenticated arbitrary file read via improper path confinement.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade GitLab CE/EE to >= 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3, or 19.5.1.\n"
                f"2. Restrict unauthenticated public access to GitLab web and API endpoints where applicable."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "GitLab CE/EE service detected (version concealed behind authentication)."
            details = (
                f"GitLab service detected on {target_ip}; manual version verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: GitLab instance on {target_ip} meets the minimum patched release:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected GitLab CE/EE services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for GitLab CE/EE (CVE-2026-110264 & CVE-2026-85706)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_GITLAB_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = GitLabAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a GitLab version affected by CVE-2026-110264.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes GitLab services requiring version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
