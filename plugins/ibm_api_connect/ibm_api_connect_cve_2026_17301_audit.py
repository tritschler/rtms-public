"""
ibm_api_connect_cve_2026_17301_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 443, 8443, 9443, 3000, 8080, 80) for
IBM API Connect instances (10.0.8.0 - 10.0.8.12 and 12.1.0.0 - 12.1.1.2)
affected by the critical November 2026 security bulletin, including:
  - CVE-2026-17301 (CVSS 9.8 Critical): Unauthenticated authentication bypass
    due to improper verification of a cryptographic signature.
  - CVE-2026-17408 (CVSS 9.8 Critical): Unauthenticated remote OS command
    execution via improper neutralization of special elements.
  - CVE-2026-17360 / CVE-2026-17403 (CVSS 9.8 / 9.0 Critical): Full administrative
    control via hard-coded credentials.
  - CVE-2026-16720 (CVSS 9.8 Critical): Directory service authentication bypass
    allowing remote attackers to obtain valid access tokens for arbitrary users.
  - CVE-2026-17313 / CVE-2026-17340 (CVSS 9.8 Critical): Unauthenticated gateway
    configuration takeover and path traversal RCE.

CVSS Score: 9.8 (Critical) - CWE-347 / CWE-78 / CWE-798 / CWE-287
Affected Components: IBM API Connect 10.0.8.0 - 10.0.8.12 and 12.1.0.0 - 12.1.1.2.
Fixed in: IBM API Connect 10.0.8.13+ and 12.1.1.3+.

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
                return self.format_result("Skipped", details="Requirements not met (no target IBM API Connect ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard IBM API Connect HTTP/HTTPS management & gateway ports
DEFAULT_APIC_PORTS = [443, 8443, 9443, 3000, 8080, 80]
SSL_PORTS = {443, 8443, 9443}


def parse_ibm_apic_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    """
    Extracts IBM API Connect 4-part version (major, minor, mod, fix, raw_str) from:
      1. JSON metadata: {"version": "10.0.8.5"} or {"productVersion": "12.1.1.1"}
      2. Headers or HTML banners: IBM API Connect 10.0.8.12, IBM-APIConnect/12.1.0.2
      3. Version strings: 10.0.8.5 or 12.1.1.2-ifix1
    """
    if not text:
        return None

    patterns = [
        r'"(?:productVersion|apicVersion|version)"\s*:\s*"(?:IBM\s+API\s+Connect[\s/\-]*)?v?([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?(?:[\.\-\s][0-9a-zA-Z._\-]*)?"',
        r'IBM[\s\-]+API[\s\-]*Connect[\s/\-:v]*([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?\b',
        r'APIConnect[\s/\-:v]+([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?\b',
        r'^v?([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?(?:-[0-9a-zA-Z._\-]+)?$',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            mod = int(match.group(3))
            fix_raw = match.group(4)
            fix = int(fix_raw) if fix_raw is not None else 0
            raw_str = f"{major}.{minor}.{mod}.{fix_raw}" if fix_raw is not None else f"{major}.{minor}.{mod}"
            return major, minor, mod, fix, raw_str

    return None


def is_ibm_apic_vulnerable(major: int, minor: int, mod: int, fix: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates IBM API Connect version against CVE-2026-17301, CVE-2026-17408, CVE-2026-17360,
    CVE-2026-17403, and CVE-2026-16720:
      - 10.0.8.0 through 10.0.8.12 (and legacy < 10.0.8.0) -> Vulnerable (Fixed in >= 10.0.8.13)
      - 12.1.0.0 through 12.1.1.2 -> Vulnerable (Fixed in >= 12.1.1.3)
    """
    ver_display = raw_str or f"{major}.{minor}.{mod}.{fix}"

    if major == 10:
        if (minor, mod, fix) <= (0, 8, 12):
            return True, (
                f"IBM API Connect {ver_display} is affected by CVE-2026-17301 (CVSS 9.8 signature verification "
                f"auth bypass), CVE-2026-17408 (CVSS 9.8 remote OS command injection), CVE-2026-17403 "
                f"(CVSS 9.0 hard-coded credentials), and CVE-2026-16720 (CVSS 9.8 token impersonation). "
                f"Fixed in 10.0.8.13+."
            )
        return False, (
            f"IBM API Connect {ver_display} is patched in the 10.0.8.x branch (>= 10.0.8.13)."
        )

    if major == 12:
        if (minor, mod, fix) <= (1, 1, 2):
            return True, (
                f"IBM API Connect {ver_display} is affected by CVE-2026-17301 (CVSS 9.8 signature verification "
                f"auth bypass), CVE-2026-17408 (CVSS 9.8 remote OS command injection), CVE-2026-17360 "
                f"(CVSS 9.8 hard-coded administrative credentials), and CVE-2026-16720 (CVSS 9.8 token impersonation). "
                f"Fixed in 12.1.1.3+."
            )
        return False, (
            f"IBM API Connect {ver_display} is patched in the 12.1.x branch (>= 12.1.1.3)."
        )

    if major < 10:
        return True, (
            f"IBM API Connect {ver_display} belongs to an end-of-support legacy release (< 10.0.8.13) "
            f"exposed to multiple critical vulnerabilities. Upgrade to 10.0.8.13+ or 12.1.1.3+."
        )

    return False, (
        f"IBM API Connect {ver_display} is not affected by CVE-2026-17301 / CVE-2026-17408."
    )


class IBMAPIConnectAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: IBM API Connect Critical Auth Bypass & RCE Audit (CVE-2026-17301 / CVE-2026-17408).
    Performs safe, read-only HTTP/HTTPS fingerprinting of IBM API Connect management and gateway endpoints.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "IBM API Connect Auth Bypass & RCE Audit (CVE-2026-17301)",
            "description": "Audits HTTP/HTTPS endpoints (ports 443, 8443, 9443, 3000, 8080, 80) for IBM API Connect instances (10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2) affected by cryptographic signature auth bypass (CVE-2026-17301), OS command injection (CVE-2026-17408), and hard-coded credentials (CVE-2026-17360).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-17301",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_APIC_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or IBM API Connect ports on the target host.
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
                    or "apic" in s_name
                    or "ibm" in s_name
                    or "datapower" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
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
        path: str = "/",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect IBM API Connect headers and portal metadata.
        """
        use_ssl = port in SSL_PORTS or port in (443, 8443, 9443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-17301)",
                "Accept": "application/json,text/html,*/*",
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
        Probes standard IBM API Connect endpoints (/api/cloud/settings, /api/cloud/version,
        /manager/, /admin/, /) to detect the service and release version.
        """
        candidate_paths = [
            "/api/cloud/settings",
            "/api/cloud/version",
            "/manager/",
            "/admin/",
            "/"
        ]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            apic_ver_hdr = headers.get("x-ibm-apiconnect-version", "") or headers.get("x-apic-version", "")
            body_lower = body.lower()
            srv_lower = server_hdr.lower()

            is_apic = (
                "ibm api connect" in body_lower
                or "apiconnect" in body_lower
                or "apiconnect" in srv_lower
                or "apic-manager" in body_lower
                or "cloud manager" in body_lower and "ibm" in body_lower
                or bool(apic_ver_hdr)
            )

            if not is_apic:
                continue

            ver_info = (
                parse_ibm_apic_version(apic_ver_hdr)
                or parse_ibm_apic_version(server_hdr)
                or parse_ibm_apic_version(body)
            )
            if ver_info:
                major, minor, mod, fix, raw_str = ver_info
                is_vuln, reason = is_ibm_apic_vulnerable(major, minor, mod, fix, raw_str)
                return {
                    "port": port,
                    "apic_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            return {
                "port": port,
                "apic_detected": True,
                "version": "Concealed (IBM API Connect version hidden)",
                "source": f"HTTP GET {path} (IBM API Connect management/portal interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"IBM API Connect detected on port {port} ({path}), but exact fixpack version is concealed. "
                    f"Verify in IBM Cloud Manager that the deployment is updated to 10.0.8.13+ or 12.1.1.3+."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified IBM API Connect ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("apic_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] IBM API Connect v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] IBM API Connect v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-17301 / CVE-2026-17408 / CVE-2026-17360 confirmed on {target_ip}.\n"
                f"Vulnerable IBM API Connect instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-17301 / CVE-2026-17408 / CVE-2026-17360 - CVSS 9.8):\n"
                f"The target host {target_ip} runs a vulnerable IBM API Connect release.\n"
                f"Flaw Overview:\n"
                f"1. CVE-2026-17301 (CVSS 9.8): Improper verification of cryptographic signatures allows "
                f"unauthenticated remote attackers to bypass authentication.\n"
                f"2. CVE-2026-17408 (CVSS 9.8): Improper neutralization of special elements in OS commands allows "
                f"remote attackers to execute arbitrary code on the underlying host.\n"
                f"3. CVE-2026-17360 / CVE-2026-17403 (CVSS 9.8 / 9.0): Hard-coded credentials allow remote attackers "
                f"to gain full administrative control.\n"
                f"4. CVE-2026-16720 (CVSS 9.8): Insufficient enforcement of directory service authentication allows "
                f"remote attackers to obtain valid access tokens for arbitrary users.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade IBM API Connect 10.0.8.x immediately to version 10.0.8.13 or later.\n"
                f"2. Upgrade IBM API Connect 12.1.x immediately to version 12.1.1.3 or later.\n"
                f"3. Restrict external network exposure of Cloud Manager and Management APIs (/api/cloud, /manager) to trusted admin networks."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "IBM API Connect active with concealed version."
            details = (
                f"IBM API Connect detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: IBM API Connect instances on {target_ip} are running versions resistant to CVE-2026-17301:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable IBM API Connect instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for IBM API Connect CVE-2026-17301 / CVE-2026-17408 / CVE-2026-17360."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[443, 8443, 9443, 3000, 8080, 80],
        help="Ports to inspect (default: 443 8443 9443 3000 8080 80)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-17301 Auditor (IBM API Connect)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = IBMAPIConnectAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-17301!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual IBM API Connect version verification.\n")
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
