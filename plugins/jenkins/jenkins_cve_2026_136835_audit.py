"""
jenkins_cve_2026_136835_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS metadata and plugin version verification
for Jenkins Automation Server running the Jenkins Script Security Plugin
(script-security <= 1436.v1082791135e4) against CVE-2026-136835.

Advisory Summary:
  - CVE-2026-136835 (CVSS 9.9 Critical): Sandbox bypass in Jenkins Script Security Plugin
    <= 1436.v1082791135e4 due to insufficient validation of @Builder annotation
    builderStrategy members when referenced via partially qualified class names.

Affected Versions:
  - Jenkins Script Security Plugin (script-security) <= 1436.v1082791135e4 (< 1437)

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
                return self.format_result("Skipped", details="Requirements not met (no target Jenkins ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_JENKINS_PORTS = [8080, 8443, 80, 443, 8000, 8888]
SSL_PORTS = {443, 8443, 9443}
MAX_VULNERABLE_RELEASE = (1436, 0)


def parse_jenkins_script_security_version(text: str) -> Optional[Tuple[int, int, str]]:
    """
    Extracts Jenkins Script Security Plugin version tuple (release_num, minor_num, raw_str)
    from Jenkins Plugin Manager JSON/XML API responses, HTML pages, or telemetry banners.

    Examples:
      - '{"shortName":"script-security","version":"1436.v1082791135e4"}' -> (1436, 0, '1436.v1082791135e4')
      - 'Jenkins Script Security Plugin 1437.v9a8b7c6d5e4f' -> (1437, 0, '1437.v9a8b7c6d5e4f')
      - 'script-security: 1368.vb_b_402e3547e7' -> (1368, 0, '1368.vb_b_402e3547e7')
      - 'script-security/1.78' -> (1, 78, '1.78')
    """
    if not text:
        return None

    patterns = [
        r'"shortName"\s*:\s*"script-security"\s*,\s*"version"\s*:\s*"(([0-9]+)(?:\.([0-9]+))?(?:\.v[0-9a-fA-F_]+)?)"',
        r'"version"\s*:\s*"(([0-9]+)(?:\.([0-9]+))?(?:\.v[0-9a-fA-F_]+)?)"\s*,\s*"shortName"\s*:\s*"script-security"',
        r"<shortName>\s*script-security\s*</shortName>\s*<version>\s*(([0-9]+)(?:\.([0-9]+))?(?:\.v[0-9a-fA-F_]+)?)\s*</version>",
        r"(?:Jenkins\s+Script\s+Security(?:\s+Plugin)?|script-security)[\s:/=\"']+v?(([0-9]+)(?:\.([0-9]+))?(?:\.v[0-9a-fA-F_]+)?)\b",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if match:
            raw_str = match.group(1)
            major = int(match.group(2))
            minor = int(match.group(3)) if match.group(3) is not None else 0
            return major, minor, raw_str

    return None


def is_jenkins_script_security_vulnerable(
    release_num: int,
    minor_num: int = 0,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether a Jenkins Script Security Plugin version is affected by
    CVE-2026-136835 (<= 1436.v1082791135e4).
    """
    ver_tuple = (release_num, minor_num)
    ver_display = raw_str or (f"{release_num}.{minor_num}" if minor_num else f"{release_num}")

    if ver_tuple <= MAX_VULNERABLE_RELEASE:
        return True, (
            f"Jenkins Script Security Plugin {ver_display} is <= 1436.v1082791135e4 and is "
            f"affected by CVE-2026-136835 (CVSS 9.9 Critical)."
        )

    return False, (
        f"Jenkins Script Security Plugin {ver_display} is patched (> 1436.v1082791135e4) "
        f"against CVE-2026-136835."
    )


class JenkinsScriptSecurityAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Jenkins Script Security Plugin Version Compliance Audit (CVE-2026-136835).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Jenkins Script Security Plugin Sandbox Bypass Audit (CVE-2026-136835)",
            "description": (
                "Passive version compliance check for Jenkins Script Security Plugin "
                "<= 1436.v1082791135e4 against CVE-2026-136835 (CVSS 9.9)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-136835",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_JENKINS_PORTS.copy()
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

                if port in self.target_ports or "jenkins" in s_name or "http" in s_name or "jetty" in s_name:
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
        path: str = "/login",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-136835)",
                "Accept": "application/json,application/xml,text/html,*/*",
                "Connection": "close",
            }
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            raw_body = resp.read(32768).decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return {
                "port": port,
                "path": path,
                "status_code": resp.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:16384],
            }
        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"Jenkins HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/pluginManager/api/json?depth=1&tree=plugins[shortName,version]", "Jenkins Plugin Manager REST API"),
            ("/pluginManager/api/xml?depth=1", "Jenkins Plugin Manager XML API"),
            ("/login", "Jenkins Web Login / Metadata Headers"),
            ("/", "HTTP Root Banner / Headers"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            if (
                "x-jenkins" in headers
                or "script-security" in combined.lower()
                or "jenkins" in combined.lower()
            ):
                ver_info = parse_jenkins_script_security_version(combined)
                if ver_info:
                    rel_num, minor_num, ver_str = ver_info
                    is_vuln, reason = is_jenkins_script_security_vulnerable(rel_num, minor_num, ver_str)
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
                    f"- [{port_label}] Jenkins Script Security Plugin {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Jenkins Script Security Plugin {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-136835 affected Jenkins Script Security Plugin detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-136835 - CVSS 9.9):\n"
                f"The target host {target_ip} exposes a Jenkins instance with an unpatched Script Security Plugin "
                f"(<= 1436.v1082791135e4).\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-136835 (CVSS 9.9): Sandbox bypass via @Builder annotation builderStrategy validation flaw.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Jenkins Script Security Plugin (script-security) to a release newer than 1436.v1082791135e4.\n"
                f"2. Restrict network access to Jenkins management and pipeline configuration interfaces."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Jenkins Script Security Plugin on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Jenkins Script Security Plugin versions detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Jenkins Script Security Plugin (CVE-2026-136835)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_JENKINS_PORTS,
        help="Ports to inspect (default: 8080 8443 80 443 8000 8888)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = JenkinsScriptSecurityAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Jenkins Script Security Plugin version affected by CVE-2026-136835.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
