"""
sap_netweaver_cve_2026_89126_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and version verification for
SAP Web Dispatcher, SAP NetWeaver AS ABAP (ICM), and SAP Gateway endpoints
to check patch compliance against the November 2026 SAP Critical Advisories:
  - CVE-2026-89126 (CVSS 10.0): SAP Web Dispatcher network input validation flaw
  - CVE-2026-76964 (CVSS 10.0): SAP NetWeaver AS ABAP (ICM) network input validation flaw
  - CVE-2026-89103 (CVSS 10.0): SAP Gateway default Access Control List (ACL) privilege issue
  - CVE-2026-120017 (CVSS 10.0): SAP NetWeaver AS ABAP SAML2 authentication assertion check
  - CVE-2026-76965 (CVSS 9.9): SAP NetWeaver AS ABAP & ABAP Platform missing authorization check
  - CVE-2026-89119 (CVSS 9.6): SAP Web Dispatcher & ICM administrative request validation flaw
  - CVE-2026-109803 (CVSS 9.9): SAP NetWeaver KM XML Forms XSL transformation restriction flaw
  - CVE-2026-109795 (CVSS 9.9): SAP NetWeaver remote-enabled functionality authorization check

Affected Kernel / Release Branches:
  - SAP Web Dispatcher / ICM / Kernel: 7.22, 7.53, 7.54, 7.77, 7.93, 8.04, 9.16, 9.18, 9.20, 9.21
    (prior to November 2026 SAP Security Patch Day minimum patch levels).

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
                return self.format_result("Skipped", details="Requirements not met (no target SAP HTTP/HTTPS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_SAP_PORTS = [80, 443, 8000, 8001, 8080, 8443, 44300, 50000, 50001]
SSL_PORTS = {443, 8443, 44300, 50001, 9443}

# Minimum patched Kernel / Web Dispatcher patch levels per release branch (Nov 2026 SAP Patch Day)
MIN_SAFE_PATCH_LEVELS: Dict[str, int] = {
    "7.22": 1400,
    "7.53": 1400,
    "7.54": 500,
    "7.77": 700,
    "7.93": 300,
    "8.04": 400,
    "9.16": 200,
    "9.18": 150,
    "9.20": 120,
    "9.21": 100,
}


def parse_sap_version(text: str) -> Optional[Tuple[str, Optional[int], str]]:
    """
    Extracts SAP Web Dispatcher / NetWeaver ICM release branch and optional patch level
    from HTTP Server headers or ping page metadata.
    Returns (branch_str, patch_level_or_None, raw_match_str).
    Examples:
      - 'SAP Web Dispatcher/7.77.0 pl 450' -> ('7.77', 450, '7.77 (pl 450)')
      - 'SAP NetWeaver Application Server / ABAP 753 (Kernel 7.53 Patch 1200)' -> ('7.53', 1200, '7.53 (pl 1200)')
      - 'SAP Web Dispatcher/9.20' -> ('9.20', None, '9.20')
    """
    if not text:
        return None

    patch_match = re.search(
        r"(?:SAP\s+(?:Web\s+Dispatcher|NetWeaver[^;\r\n]*|Internet\s+Communication\s+Manager|Kernel)|ICM|WEBDISP|KRNL64(?:N?UC)?)"
        r"[^0-9\r\n]*([789]\.[0-9]{2})(?:\.[0-9]+)?(?:[^0-9\r\n]+(?:pl|patch(?:\s*level)?)\s*[:=]?\s*([0-9]+))?",
        text,
        re.IGNORECASE,
    )
    if patch_match:
        branch = patch_match.group(1)
        pl_raw = patch_match.group(2)
        if pl_raw is None:
            secondary_pl = re.search(r"(?:pl|patch(?:\s*level)?)\s*[:=]?\s*([0-9]+)", text, re.IGNORECASE)
            if secondary_pl:
                pl_raw = secondary_pl.group(1)
        patch_level = int(pl_raw) if pl_raw is not None else None
        raw_str = f"{branch} (pl {patch_level})" if patch_level is not None else branch
        return branch, patch_level, raw_str

    abap_code_match = re.search(
        r"SAP\s+NetWeaver\s+Application\s+Server[^0-9\r\n]*(722|753|754|777|793|804|916|918|920|921)\b",
        text,
        re.IGNORECASE,
    )
    if abap_code_match:
        code = abap_code_match.group(1)
        branch = f"{code[0]}.{code[1:]}"
        secondary_pl = re.search(r"(?:pl|patch(?:\s*level)?)\s*[:=]?\s*([0-9]+)", text, re.IGNORECASE)
        patch_level = int(secondary_pl.group(1)) if secondary_pl else None
        raw_str = f"{branch} (pl {patch_level})" if patch_level is not None else branch
        return branch, patch_level, raw_str

    return None


def is_sap_version_vulnerable(branch: str, patch_level: Optional[int]) -> Tuple[bool, str]:
    """
    Evaluates whether a SAP Web Dispatcher / NetWeaver Kernel branch and patch level
    are affected by CVE-2026-89126, CVE-2026-76964, CVE-2026-89103, CVE-2026-120017,
    CVE-2026-76965, and CVE-2026-89119.
    """
    if branch not in MIN_SAFE_PATCH_LEVELS:
        return False, f"SAP release branch {branch} is not listed in the affected November 2026 kernel branches."

    min_safe_pl = MIN_SAFE_PATCH_LEVELS[branch]

    if patch_level is None:
        return True, (
            f"SAP kernel/dispatcher branch {branch} is in the affected range for CVE-2026-89126, "
            f"CVE-2026-76964, and CVE-2026-89103 (CVSS 10.0) and exposes no patch level Proof >= pl {min_safe_pl}."
        )

    if patch_level < min_safe_pl:
        return True, (
            f"SAP kernel/dispatcher {branch} pl {patch_level} is affected by CVE-2026-89126, "
            f"CVE-2026-76964, and CVE-2026-89103 (requires patch level >= pl {min_safe_pl})."
        )

    return False, (
        f"SAP kernel/dispatcher {branch} pl {patch_level} meets or exceeds the minimum safe patch level "
        f"(>= pl {min_safe_pl}) for CVE-2026-89126 / CVE-2026-76964."
    )


class SapNetWeaverAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: SAP Web Dispatcher & NetWeaver Compliance Audit (CVE-2026-89126).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "SAP Web Dispatcher & NetWeaver Compliance Audit (CVE-2026-89126)",
            "description": (
                "Passive version compliance check for SAP Web Dispatcher, SAP NetWeaver AS ABAP (ICM), "
                "and SAP Gateway against CVE-2026-89126, CVE-2026-76964, CVE-2026-89103, and CVE-2026-120017."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-89126",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_SAP_PORTS.copy()
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
                    or "sap" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
                ):
                    self.discovered_ports.append(port)

        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.target_ports or port in (80, 443, 8000, 8080, 8443):
                        self.discovered_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/sap/public/ping",
        timeout: float = 4.0,
    ) -> Optional[Dict[str, Any]]:
        use_ssl = port in SSL_PORTS or port in (443, 8443, 44300, 50001)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-89126)",
                "Accept": "text/html,text/plain,application/json,*/*",
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
            ("/sap/public/ping", "SAP /sap/public/ping status endpoint"),
            ("/sap/public/icman/ping", "SAP ICM /sap/public/icman/ping endpoint"),
            ("/", "SAP root HTTP response"),
        ]

        sap_detected = False
        detected_source = ""

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            sap_server_hdr = headers.get("sap-server", "")
            combined = f"{server_hdr}\n{sap_server_hdr}\n{body}"
            combined_lower = combined.lower()

            if (
                "sap web dispatcher" in combined_lower
                or "sap netweaver" in combined_lower
                or "sap internet communication manager" in combined_lower
                or "sap-system" in headers
                or "sap-server" in headers
            ):
                sap_detected = True
                detected_source = f"{source_label} (Server header / response)"

                ver_info = parse_sap_version(combined)
                if ver_info:
                    branch, patch_level, ver_str = ver_info
                    is_vuln, reason = is_sap_version_vulnerable(branch, patch_level)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": detected_source,
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        if sap_detected:
            return {
                "port": port,
                "service_detected": True,
                "version": "Concealed",
                "source": detected_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "SAP Web Dispatcher / NetWeaver HTTP service is active, but the exact kernel/patch "
                    "version string is concealed (`is/HTTP/show_detailed_errors = FALSE`). Verify SAP "
                    "November 2026 Security Patch Day notes are applied."
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
                    f"- [{port_label}] SAP version {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] SAP version {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-89126 / CVE-2026-76964 / CVE-2026-89103 affected SAP version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-89126 / CVE-2026-76964 / CVE-2026-89103 - CVSS 10.0):\n"
                f"The target host {target_ip} runs an affected SAP Web Dispatcher / NetWeaver kernel version.\n\n"
                f"Associated November 2026 SAP Critical Advisories:\n"
                f"- CVE-2026-89126 (CVSS 10.0): SAP Web Dispatcher network input validation flaw\n"
                f"- CVE-2026-76964 (CVSS 10.0): SAP NetWeaver AS ABAP (ICM) network input validation flaw\n"
                f"- CVE-2026-89103 (CVSS 10.0): SAP Gateway default Access Control List (ACL) privilege issue\n"
                f"- CVE-2026-120017 (CVSS 10.0): SAP NetWeaver AS ABAP SAML2 authentication assertion verification\n"
                f"- CVE-2026-76965 (CVSS 9.9): SAP NetWeaver AS ABAP internal authorization check\n"
                f"- CVE-2026-89119 (CVSS 9.6): SAP Web Dispatcher & ICM administrative request validation\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Apply the November 2026 SAP Security Patch Day kernel and Web Dispatcher updates.\n"
                f"2. Restrict external access to SAP Web Dispatcher admin interfaces and SAP Gateway ports.\n"
                f"3. Review `gw/acl_mode` and `secinfo`/`reginfo` ACL rules on SAP Gateway instances."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "SAP Web Dispatcher / NetWeaver service detected with concealed version banner."
            details = (
                f"SAP HTTP service detected on {target_ip}, but version banners are suppressed:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: SAP instances on {target_ip} meet the minimum patched kernel levels:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected SAP Web Dispatcher or NetWeaver HTTP services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for SAP Web Dispatcher & NetWeaver (CVE-2026-89126 / CVE-2026-76964)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_SAP_PORTS,
        help="Ports to inspect (default: 80 443 8000 8001 8080 8443 44300 50000 50001)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="HTTP timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = SapNetWeaverAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} requires SAP November 2026 Security Patch Day updates (CVE-2026-89126).\n")
        print(res.get("details", ""))
        sys.exit(1)
    elif status == "Warning":
        print(f"[WARNING] {args.target} requires manual SAP kernel version verification.\n")
        print(res.get("details", ""))
        sys.exit(0)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
