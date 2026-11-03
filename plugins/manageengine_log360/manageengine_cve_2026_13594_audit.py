"""
manageengine_cve_2026_13594_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 80, 443, 8080, 8095, 8400, 8443) for Zoho ManageEngine
Log360 and EventLog Analyzer deployments (builds <= 13062) vulnerable to CVE-2026-13594
(Unauthenticated / Unauthorized Product Access).

CVSS Score: 9.1 (Critical) - CWE-287 / CWE-306 (Improper Authentication / Missing Auth)
Affected Components: Zoho ManageEngine Log360 and EventLog Analyzer builds <= 13062.
Fixed in: Build 13063 and later.

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

# Support both RTMS Scanner modular runtime and standalone CLI execution
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
                "details": details
            }

        def execute(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
            if hasattr(self, "check_requirements") and not self.check_requirements(target_ip, target_services):
                return self.format_result("Skipped", details="Requirements not met (no target ManageEngine ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Default ports for EventLog Analyzer (8400), Log360 (8095), and standard web proxies
DEFAULT_MANAGEENGINE_PORTS = [80, 443, 8080, 8095, 8400, 8443]
SSL_PORTS = {443, 8443, 9443}
MAX_VULNERABLE_BUILD = 13062


def parse_manageengine_build(text: str) -> Optional[int]:
    """
    Extracts the 4- or 5-digit ManageEngine build number (e.g. 13062, 13060, 13063) from:
      1. JSON metadata: "BUILD_NUMBER":"13062", "buildNumber": 13062, "build_no": "13062"
      2. Asset query strings: ?build=13062, ?v=13062, .js?13062
      3. HTML / JS strings: Build 13062, buildVersion = '13062'
    """
    if not text:
        return None

    patterns = [
        r'"(?:BUILD_NUMBER|buildNumber|build_no|buildVersion|build)"\s*:\s*"?([1-9][0-9]{3,4})"?',
        r'\b(?:Build|build|build_number|buildVersion)\s*[:=#]?\s*[\'"]?([1-9][0-9]{3,4})[\'"]?\b',
        r'\?(?:build|ver|v)=([1-9][0-9]{3,4})\b',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            build_num = int(match.group(1))
            if 5000 <= build_num <= 99999:
                return build_num

    return None


def is_manageengine_build_vulnerable(build_num: int) -> Tuple[bool, str]:
    """
    Evaluates ManageEngine Log360 / EventLog Analyzer build number against CVE-2026-13594 (<= 13062).
    """
    if build_num <= MAX_VULNERABLE_BUILD:
        return True, (
            f"ManageEngine build {build_num} is vulnerable to CVE-2026-13594 "
            f"(affected: <= {MAX_VULNERABLE_BUILD}; requires upgrade to build >= 13063)."
        )

    return False, (
        f"ManageEngine build {build_num} is patched against CVE-2026-13594 "
        f"(running build >= 13063)."
    )


class ManageEngineLog360AuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Zoho ManageEngine Log360 & EventLog Analyzer Audit (CVE-2026-13594).
    Performs safe, non-destructive HTTP/HTTPS fingerprinting of ManageEngine SIEM consoles.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Zoho ManageEngine Log360 & EventLog Analyzer Audit (CVE-2026-13594)",
            "description": "Audits HTTP/HTTPS endpoints (ports 80, 443, 8080, 8095, 8400, 8443) for Zoho ManageEngine Log360 and EventLog Analyzer (builds <= 13062) vulnerable to unauthorized product access (CVE-2026-13594).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-13594",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_MANAGEENGINE_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or ManageEngine ports on the target host.
        """
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
                    or "manageengine" in s_name
                    or "eventlog" in s_name
                    or "log360" in s_name
                    or "ssl" in s_name
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
        path: str = "/event/index2.do",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect ManageEngine headers and login page.
        """
        use_ssl = port in SSL_PORTS or port in (443, 8443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-13594)",
                "Accept": "text/html,application/json,*/*",
                "Connection": "close"
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            raw_body = response.read(32768).decode("utf-8", errors="replace")

            resp_headers: Dict[str, str] = {}
            for k, v in response.getheaders():
                resp_headers[k.lower()] = v

            return {
                "port": port,
                "path": path,
                "status_code": response.status,
                "headers": resp_headers,
                "body_snippet": raw_body[:16384]
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
        """
        Probes ManageEngine Log360 and EventLog Analyzer paths to detect the product and its build number.
        """
        candidate_paths = [
            "/event/index2.do",
            "/apps/Home.do",
            "/RestAPI/GetProductInfo",
            "/",
        ]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            cookie_hdr = headers.get("set-cookie", "").lower()
            body_lower = body.lower()

            is_manageengine = (
                "eventlog analyzer" in body_lower
                or "manageengine log360" in body_lower
                or "manageengine eventlog" in body_lower
                or "log360" in body_lower and "zoho" in body_lower
                or "el_sessionid" in cookie_hdr
                or "log360" in cookie_hdr
            )

            if not is_manageengine:
                continue

            product_name = "ManageEngine Log360" if "log360" in body_lower else "ManageEngine EventLog Analyzer"
            build_num = parse_manageengine_build(body)

            if build_num is not None:
                is_vuln, reason = is_manageengine_build_vulnerable(build_num)
                return {
                    "port": port,
                    "manageengine_detected": True,
                    "product": product_name,
                    "build": str(build_num),
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            return {
                "port": port,
                "manageengine_detected": True,
                "product": product_name,
                "build": "Concealed (build number hidden)",
                "source": f"HTTP GET {path}",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"{product_name} detected on port {port} ({path}), but exact build number is "
                    f"concealed. Verify in Support > About that the installation runs build >= 13063."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified ManageEngine ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("manageengine_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] {result.get('product')} (Build {result.get('build')}) detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] {result.get('product')} (Build {result.get('build')}) detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-13594 confirmed on {target_ip}.\n"
                f"Vulnerable ManageEngine SIEM instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-13594 - CVSS 9.1):\n"
                f"The target host {target_ip} runs a vulnerable Zoho ManageEngine Log360 or EventLog Analyzer build (<= 13062).\n"
                f"Flaw Overview:\n"
                f"Zoho Corporation's ManageEngine Log360 and EventLog Analyzer versions 13062 and below contain "
                f"an authentication/access control flaw that allows an unauthenticated remote adversary to gain "
                f"unauthorized access to the SIEM product and sensitive security telemetry.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Apply the official Zoho ManageEngine service pack to upgrade to build 13063 or later.\n"
                f"2. Restrict external access to ManageEngine web ports (8400, 8095, 8443) to trusted management subnets."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "ManageEngine Log360 / EventLog Analyzer active with concealed build number."
            details = (
                f"ManageEngine SIEM console detected on {target_ip} with concealed build metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: ManageEngine instances on {target_ip} are running patched builds (>= 13063) "
                f"resistant to CVE-2026-13594:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable ManageEngine Log360 or EventLog Analyzer instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for Zoho ManageEngine Log360 & EventLog Analyzer CVE-2026-13594."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 8080, 8095, 8400, 8443],
        help="Ports to inspect (default: 80 443 8080 8095 8400 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-13594 Auditor (ManageEngine)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = ManageEngineLog360AuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-13594!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual build verification.\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(0)
    elif status == "OK":
        print(f"✅ [SAFE] {args.target} passed audit.")
        print(f"   {result.get('details', '')}\n")
        sys.exit(0)
    else:
        print(f"ℹ️  [{status}] {result.get('details', '')}\n")
        sys.exit(0)
