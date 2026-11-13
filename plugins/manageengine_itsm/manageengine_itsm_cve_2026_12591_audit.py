"""
manageengine_itsm_cve_2026_12591_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS portal and build metadata verification for
Zoho ManageEngine ITSM & Infrastructure Management deployments against:
  - CVE-2026-12591 (CVSS 9.9 Critical): Privilege escalation and remote code execution via
    delegated administration interface in ManageEngine M365 Manager Plus (< 4818).
  - CVE-2026-12507 (CVSS 9.1 Critical): Authenticated remote code execution in Reports module in
    ManageEngine ServiceDesk Plus (< 15290), AssetExplorer (< 7860), ServiceDesk Plus MSP (< 15150),
    and SupportCenter Plus (< 15150).
  - CVE-2026-19422 (CVSS 9.1 Critical): Unauthenticated bypass in Windows DNS & DHCP agent
    synchronization APIs in ManageEngine DDI Central (< 6301).

Affected Builds:
  - ManageEngine M365 Manager Plus prior to build 4818 (Fixed in 4818+)
  - ManageEngine ServiceDesk Plus prior to build 15290 (Fixed in 15290+)
  - ManageEngine ServiceDesk Plus MSP prior to build 15150 (Fixed in 15150+)
  - ManageEngine SupportCenter Plus prior to build 15150 (Fixed in 15150+)
  - ManageEngine AssetExplorer prior to build 7860 (Fixed in 7860+)
  - ManageEngine DDI Central prior to build 6301 (Fixed in 6301+)

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
                return self.format_result("Skipped", details="Requirements not met (no target ManageEngine ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_ME_ITSM_PORTS = [80, 443, 8080, 8443, 8363, 8553]
SSL_PORTS = {443, 8443, 8553, 9443}

PRODUCT_THRESHOLDS: Dict[str, Tuple[int, str]] = {
    "M365 Manager Plus": (4818, "CVE-2026-12591 (CVSS 9.9)"),
    "ServiceDesk Plus MSP": (15150, "CVE-2026-12507 (CVSS 9.1)"),
    "ServiceDesk Plus": (15290, "CVE-2026-12507 (CVSS 9.1)"),
    "SupportCenter Plus": (15150, "CVE-2026-12507 (CVSS 9.1)"),
    "AssetExplorer": (7860, "CVE-2026-12507 (CVSS 9.1)"),
    "DDI Central": (6301, "CVE-2026-19422 (CVSS 9.1)"),
}


def parse_me_itsm_product_and_build(text: str) -> Optional[Tuple[str, Optional[int]]]:
    """
    Identifies the ManageEngine product name and extracts its 4- or 5-digit build number
    from web portal HTML/JSON metadata or static asset query strings.
    """
    if not text:
        return None

    text_lower = text.lower()
    detected_product: Optional[str] = None

    if "m365 manager plus" in text_lower or "o365managerplus" in text_lower:
        detected_product = "M365 Manager Plus"
    elif "servicedesk plus msp" in text_lower or "sdpmsp" in text_lower:
        detected_product = "ServiceDesk Plus MSP"
    elif "servicedesk plus" in text_lower or "sdp-webclient" in text_lower:
        detected_product = "ServiceDesk Plus"
    elif "supportcenter plus" in text_lower:
        detected_product = "SupportCenter Plus"
    elif "assetexplorer" in text_lower or "asset explorer" in text_lower:
        detected_product = "AssetExplorer"
    elif "ddi central" in text_lower or "ddicentral" in text_lower:
        detected_product = "DDI Central"

    if not detected_product:
        return None

    build_patterns = [
        r'"(?:BUILD_NUMBER|buildNumber|build_no|buildVersion|build)"\s*:\s*"?([1-9][0-9]{3,4})"?',
        r'\b(?:Build|build|build_number|buildVersion)\s*[:=#-]?\s*[\'"]?([1-9][0-9]{3,4})[\'"]?\b',
        r'\?(?:build|ver|v)=([1-9][0-9]{3,4})\b',
    ]

    for pat in build_patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            build_num = int(match.group(1))
            if 3000 <= build_num <= 99999:
                return detected_product, build_num

    return detected_product, None


def is_me_itsm_build_vulnerable(product: str, build_num: int) -> Tuple[bool, str]:
    """
    Evaluates whether a detected ManageEngine ITSM/DDI/M365 product build is affected
    by CVE-2026-12591, CVE-2026-12507, or CVE-2026-19422.
    """
    threshold_info = PRODUCT_THRESHOLDS.get(product)
    if not threshold_info:
        return False, f"ManageEngine {product} build {build_num} is not in the target product matrix."

    min_patched_build, cve_label = threshold_info
    if build_num < min_patched_build:
        return True, (
            f"ManageEngine {product} build {build_num} is prior to {min_patched_build} and is "
            f"affected by {cve_label}."
        )

    return False, (
        f"ManageEngine {product} build {build_num} is patched (>= {min_patched_build}) against {cve_label}."
    )


class ManageEngineITSMAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Zoho ManageEngine M365 Manager Plus, ServiceDesk Plus, AssetExplorer &
    DDI Central Compliance Audit (CVE-2026-12591, CVE-2026-12507, CVE-2026-19422).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Zoho ManageEngine ITSM & M365/DDI Suite Compliance Audit (CVE-2026-12591)",
            "description": (
                "Passive build compliance check for ManageEngine M365 Manager Plus (< 4818, CVE-2026-12591), "
                "ServiceDesk Plus (< 15290), AssetExplorer (< 7860), SupportCenter Plus (< 15150, CVE-2026-12507), "
                "and DDI Central (< 6301, CVE-2026-19422)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-12591",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_ME_ITSM_PORTS.copy()
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
                    or "manageengine" in s_name
                    or "servicedesk" in s_name
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-12591)",
                "Accept": "text/html,application/json,*/*",
                "Connection": "close",
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
                "body_snippet": raw_body[:16384],
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
            "/",
            "/mc/",
            "/RestAPI/GetProductInfo",
            "/HomePage.do",
        ]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            body = probe.get("body_snippet", "")
            parsed = parse_me_itsm_product_and_build(body)
            if not parsed:
                continue

            product, build_num = parsed
            if build_num is not None:
                is_vuln, reason = is_me_itsm_build_vulnerable(product, build_num)
                return {
                    "port": port,
                    "service_detected": True,
                    "product": product,
                    "build": str(build_num),
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason,
                }

            min_build, cve_label = PRODUCT_THRESHOLDS.get(product, (0, "CVE-2026-12591"))
            return {
                "port": port,
                "service_detected": True,
                "product": product,
                "build": "Concealed",
                "source": f"HTTP GET {path}",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"ManageEngine {product} detected on port {port} ({path}), but build number is concealed. "
                    f"Verify build >= {min_build} for {cve_label} compliance."
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
                    f"- [{port_label}] ManageEngine {result.get('product')} (Build {result.get('build')}) "
                    f"detected via {result.get('source')}. Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] ManageEngine {result.get('product')} (Build {result.get('build')}) "
                    f"detected via {result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-12591 / CVE-2026-12507 / CVE-2026-19422 affected ManageEngine build detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-12591 / CVE-2026-12507 / CVE-2026-19422 - CVSS 9.1-9.9):\n"
                f"The target host {target_ip} runs an outdated Zoho ManageEngine product build.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-12591 (CVSS 9.9): Privilege escalation / RCE in ManageEngine M365 Manager Plus (< 4818).\n"
                f"- CVE-2026-12507 (CVSS 9.1): Authenticated RCE in Reports module in ServiceDesk Plus (< 15290), "
                f"AssetExplorer (< 7860), ServiceDesk Plus MSP (< 15150), and SupportCenter Plus (< 15150).\n"
                f"- CVE-2026-19422 (CVSS 9.1): Authentication bypass in DNS/DHCP agent sync APIs in DDI Central (< 6301).\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Apply the official Zoho ManageEngine service pack (>= 4818 for M365 Manager Plus, "
                f">= 15290 for ServiceDesk Plus, >= 7860 for AssetExplorer, >= 6301 for DDI Central).\n"
                f"2. Restrict administrative web portals and agent synchronization APIs to trusted internal networks."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "ManageEngine ITSM/DDI service detected (build number concealed)."
            details = (
                f"ManageEngine console detected on {target_ip}; manual build verification required:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: ManageEngine instance on {target_ip} meets the minimum patched build:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected ManageEngine M365 Manager Plus, ServiceDesk Plus, AssetExplorer, or DDI Central instances detected.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive build compliance check for Zoho ManageEngine ITSM & M365/DDI Suite (CVE-2026-12591 / CVE-2026-12507 / CVE-2026-19422)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_ME_ITSM_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443 8363 8553)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = ManageEngineITSMAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a ManageEngine build affected by CVE-2026-12591 / CVE-2026-12507 / CVE-2026-19422.\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} exposes ManageEngine services requiring build verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
