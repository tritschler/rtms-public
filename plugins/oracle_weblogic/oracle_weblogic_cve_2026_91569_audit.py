"""
oracle_weblogic_cve_2026_91569_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and console version verification for
Oracle WebLogic Server against the November 2026 Oracle Critical Patch Update (7 CVEs):
  - CVE-2026-91569 (CVSS 10.0 Critical): Unauthenticated HTTP compromise in TopLink Integration.
  - CVE-2026-91570 (CVSS 9.8 Critical): Unauthenticated HTTP compromise in TopLink Integration.
  - CVE-2026-91583 (CVSS 9.8 Critical): Unauthenticated HTTP compromise in TopLink Integration.
  - CVE-2026-91585 (CVSS 9.8 Critical): Unauthenticated TCP compromise in TopLink Integration.
  - CVE-2026-91470 (CVSS 9.8 Critical): Unauthenticated T3/IIOP compromise in WebLogic Core.
  - CVE-2026-91456 (CVSS 9.8 Critical): Unauthenticated SOAP compromise in WebLogic Core.
  - CVE-2026-91469 (CVSS 9.4 Critical): Unauthenticated HTTP compromise / DoS in WebLogic Core.

Affected Versions:
  - Oracle WebLogic Server: 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, and 15.1.1.0.0
    (without the November 2026 Critical Patch Update / PSU >= 261117).

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
                return self.format_result("Skipped", details="Requirements not met (no target WebLogic ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_WEBLOGIC_PORTS = [7001, 7002, 8001, 8002, 9002, 80, 443, 8080, 8443]
SSL_PORTS = {443, 7002, 8002, 8443, 9002}
AFFECTED_BRANCHES = {
    (10, 3, 6, 0),
    (12, 1, 3, 0),
    (12, 2, 1, 3),
    (12, 2, 1, 4),
    (14, 1, 1, 0),
    (14, 1, 2, 0),
    (15, 1, 1, 0),
}
MIN_NOV_2026_PSU = 261117


def parse_weblogic_version(text: str) -> Optional[Tuple[int, int, int, int, Optional[int], str]]:
    """
    Extracts Oracle WebLogic Server 4-part version (v1, v2, v3, v4, psu_yymmdd, raw_str)
    from HTTP headers, WebLogic Admin Console login page, or T3 HELO greeting.

    Examples:
      - 'WebLogic Server 14.1.1.0.0' -> (14, 1, 1, 0, None, '14.1.1.0.0')
      - 'WebLogic Server Version: 12.2.1.4.261015' -> (12, 2, 1, 4, 261015, '12.2.1.4.261015')
      - 'WebLogic Server 15.1.1.0.261117' -> (15, 1, 1, 0, 261117, '15.1.1.0.261117')
      - 'HELO:12.2.1.4.0.false' -> (12, 2, 1, 4, None, '12.2.1.4.0')
    """
    if not text:
        return None

    patterns = [
        r"(?:WebLogic(?:\s+Server)?(?:\s+Version)?|HELO)[/\s:v]+([0-9]{2})\.([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,8}))?",
        r'id="footerVersion"[^>]*>\s*(?:WebLogic\s+Server\s+Version:\s*)?([0-9]{2})\.([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,8}))?',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            v1 = int(match.group(1))
            v2 = int(match.group(2))
            v3 = int(match.group(3))
            v4 = int(match.group(4))
            fifth_raw = match.group(5)
            psu: Optional[int] = None
            if fifth_raw is not None:
                val5 = int(fifth_raw)
                if val5 >= 200000:
                    psu = val5 if val5 < 1000000 else val5 % 1000000
                raw_str = f"{v1}.{v2}.{v3}.{v4}.{fifth_raw}"
            else:
                raw_str = f"{v1}.{v2}.{v3}.{v4}.0"
            return v1, v2, v3, v4, psu, raw_str

    return None


def is_weblogic_version_vulnerable(
    v1: int,
    v2: int,
    v3: int,
    v4: int,
    psu: Optional[int] = None,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether an Oracle WebLogic Server version is affected by the November 2026
    critical advisories: CVE-2026-91569 (CVSS 10.0), CVE-2026-91570 (9.8), CVE-2026-91583 (9.8),
    CVE-2026-91585 (9.8), CVE-2026-91470 (9.8), CVE-2026-91456 (9.8), CVE-2026-91469 (9.4).
    """
    branch = (v1, v2, v3, v4)
    ver_display = raw_str or f"{v1}.{v2}.{v3}.{v4}.0"

    if branch in AFFECTED_BRANCHES:
        if psu is not None and psu >= MIN_NOV_2026_PSU:
            return False, (
                f"Oracle WebLogic Server {ver_display} includes PSU {psu} (>= {MIN_NOV_2026_PSU}) "
                f"and is patched against CVE-2026-91569..CVE-2026-91585."
            )
        return True, (
            f"Oracle WebLogic Server {ver_display} is an affected release without verified November 2026 PSU "
            f"and is impacted by CVE-2026-91569 (CVSS 10.0), CVE-2026-91570, CVE-2026-91583, "
            f"CVE-2026-91585, CVE-2026-91470, CVE-2026-91456, and CVE-2026-91469."
        )

    if branch > (15, 1, 1, 0):
        return False, f"Oracle WebLogic Server {ver_display} is newer than 15.1.1.0.0 and not affected."

    return False, f"Oracle WebLogic Server {ver_display} is outside affected branches."


class OracleWebLogicAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Oracle WebLogic Server Version Compliance Audit
    (CVE-2026-91569, CVE-2026-91570, CVE-2026-91583, CVE-2026-91585,
    CVE-2026-91470, CVE-2026-91456, CVE-2026-91469 - CVSS 10.0 Critical).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Oracle WebLogic Server Version Compliance Audit (CVE-2026-91569)",
            "description": (
                "Passive version compliance check for Oracle WebLogic Server (12.2.1.4.0, 14.1.1.0.0, "
                "14.1.2.0.0, 15.1.1.0.0) against CVE-2026-91569 (CVSS 10.0), CVE-2026-91570, CVE-2026-91583, "
                "CVE-2026-91585, CVE-2026-91470, CVE-2026-91456, and CVE-2026-91469."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-91569",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_WEBLOGIC_PORTS.copy()
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
                    or "weblogic" in s_name
                    or "http" in s_name
                    or "t3" in s_name
                    or "iiop" in s_name
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
        path: str = "/console/login/LoginForm.jsp",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-91569)",
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
            logger.debug(f"WebLogic HTTP probe failed on {target_ip}:{port}{path}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        candidate_paths = [
            ("/console/login/LoginForm.jsp", "WebLogic Admin Console Login Page"),
            ("/", "HTTP Root Banner / Headers"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            if "weblogic" in combined.lower() or "footerversion" in combined.lower():
                ver_info = parse_weblogic_version(combined)
                if ver_info:
                    v1, v2, v3, v4, psu, ver_str = ver_info
                    is_vuln, reason = is_weblogic_version_vulnerable(v1, v2, v3, v4, psu, ver_str)
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
                    f"- [{port_label}] Oracle WebLogic Server {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Oracle WebLogic Server {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-91569..CVE-2026-91585 affected Oracle WebLogic Server detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-91569 & Related Advisories - CVSS 10.0):\n"
                f"The target host {target_ip} exposes an unpatched Oracle WebLogic Server instance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-91569 (CVSS 10.0), CVE-2026-91570 (9.8), CVE-2026-91583 (9.8), CVE-2026-91585 (9.8): "
                f"Critical vulnerabilities in WebLogic TopLink Integration over HTTP/TCP.\n"
                f"- CVE-2026-91470 (CVSS 9.8), CVE-2026-91456 (9.8), CVE-2026-91469 (9.4): "
                f"Critical vulnerabilities in WebLogic Server Core over T3, IIOP, SOAP, and HTTP.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Apply the November 2026 Oracle Critical Patch Update (PSU >= 261117) to WebLogic Server "
                f"12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, and 15.1.1.0.0.\n"
                f"2. Restrict external access to the WebLogic Admin Console (/console) and filter T3/IIOP protocols."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Oracle WebLogic Server instance on {target_ip} meets patch compliance:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Oracle WebLogic Server services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Oracle WebLogic Server (CVE-2026-91569..CVE-2026-91585)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_WEBLOGIC_PORTS,
        help="Ports to inspect (default: 7001 7002 8001 8002 9002 80 443 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = OracleWebLogicAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an Oracle WebLogic Server version affected by CVE-2026-91569.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
