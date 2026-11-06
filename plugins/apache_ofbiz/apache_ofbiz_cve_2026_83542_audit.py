"""
apache_ofbiz_cve_2026_83542_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 8443, 8080, 443, 80) for Apache OFBiz
instances (versions prior to 24.09.08) affected by CVE-2026-83542 and
CVE-2026-82907.

CVSS Score: 9.8 (Critical) - CWE-94 / CWE-294
Affected Components: Apache OFBiz versions < 24.09.08.
Fixed in: Apache OFBiz 24.09.08+.

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
                return self.format_result("Skipped", details="Requirements not met (no target Apache OFBiz ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard Apache OFBiz web ports
DEFAULT_OFBIZ_PORTS = [8443, 8080, 443, 80]
SSL_PORTS = {443, 8443}
FIXED_VERSION = (24, 9, 8)


def parse_ofbiz_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Apache OFBiz version (major, minor, patch, raw_str) from:
      1. HTML footer / release banner: Apache OFBiz 24.09.05, Release 24.09.05, v24.09.05
      2. Server or Powered-By headers: Apache-OFBiz/24.09.05
      3. Static asset query strings: ?v=24.09.05 or ?version=24.09.05
    """
    if not text:
        return None

    patterns = [
        r'Apache[\s\-]+OFBiz[/\s:]+(?:Release\s+)?v?([0-9]{2})\.([0-9]{2})(?:\.([0-9]{1,3}))?\b',
        r'(?:OFBiz(?:\s+Release)?|Release)[^0-9\r\n]{1,20}v?([0-9]{2})\.([0-9]{2})(?:\.([0-9]{1,3}))?\b',
        r'\?(?:v|ver|version)=([0-9]{2})\.([0-9]{2})(?:\.([0-9]{1,3}))?\b',
        r'"version"\s*:\s*"v?([0-9]{2})\.([0-9]{2})(?:\.([0-9]{1,3}))?"',
        r'^v?([0-9]{2})\.([0-9]{2})(?:\.([0-9]{1,3}))?$',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch_raw = match.group(3)
            patch = int(patch_raw) if patch_raw is not None else 0
            if patch_raw is not None:
                raw_str = f"{major:02d}.{minor:02d}.{int(patch_raw):02d}"
            else:
                raw_str = f"{major:02d}.{minor:02d}"
            return major, minor, patch, raw_str

    return None


def is_ofbiz_vulnerable(major: int, minor: int, patch: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates Apache OFBiz version against CVE-2026-83542 / CVE-2026-82907
    (versions < 24.09.08 are vulnerable).
    """
    ver_tuple = (major, minor, patch)
    ver_display = raw_str or f"{major:02d}.{minor:02d}.{patch:02d}"

    if ver_tuple < FIXED_VERSION:
        return True, (
            f"Apache OFBiz {ver_display} is affected by CVE-2026-83542 and CVE-2026-82907 "
            f"(CVSS 9.8 screen descriptor validation & ExternalLoginKeysManager flaw; fixed in 24.09.08)."
        )

    return False, (
        f"Apache OFBiz {ver_display} is not affected by CVE-2026-83542 / CVE-2026-82907 "
        f"(patched in >= 24.09.08)."
    )


class ApacheOfbizAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Apache OFBiz Version & Configuration Audit (CVE-2026-83542 / CVE-2026-82907).
    Performs safe, read-only HTTP/HTTPS fingerprinting of Apache OFBiz web interfaces.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Apache OFBiz Screen Descriptor & Login Key Audit (CVE-2026-83542)",
            "description": "Audits HTTP/HTTPS endpoints (ports 8443, 8080, 443, 80) for Apache OFBiz instances (< 24.09.08) affected by CVE-2026-83542 and CVE-2026-82907.",
            "severity": "CRITICAL",
            "cve": "CVE-2026-83542",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_OFBIZ_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or Apache OFBiz ports on the target host.
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
                    or "ofbiz" in s_name
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
        path: str = "/webtools/control/main",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect Apache OFBiz headers and UI markers.
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-83542)",
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                "Connection": "close"
            }

            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            raw_body = response.read(32768).decode("utf-8", errors="replace")

            resp_headers: Dict[str, str] = {}
            cookies_list: List[str] = []
            for k, v in response.getheaders():
                k_low = k.lower()
                if k_low == "set-cookie":
                    cookies_list.append(v)
                resp_headers[k_low] = v
            if cookies_list:
                resp_headers["set-cookie"] = "; ".join(cookies_list)

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
        Probes standard Apache OFBiz paths (/webtools/control/main, /ordermgr/control/main, /)
        to detect the service and release version.
        """
        candidate_paths = ["/webtools/control/main", "/ordermgr/control/main", "/"]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            set_cookie = headers.get("set-cookie", "")
            body_lower = body.lower()
            cookie_lower = set_cookie.lower()

            is_ofbiz = (
                "ofbiz.visitor" in cookie_lower
                or "apache ofbiz" in body_lower
                or "ofbiz" in server_hdr.lower()
                or "/webtools/control/" in body_lower
            )

            if not is_ofbiz:
                continue

            ver_info = parse_ofbiz_version(server_hdr) or parse_ofbiz_version(body)
            if ver_info:
                major, minor, patch, raw_str = ver_info
                is_vuln, reason = is_ofbiz_vulnerable(major, minor, patch, raw_str)
                return {
                    "port": port,
                    "ofbiz_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            return {
                "port": port,
                "ofbiz_detected": True,
                "version": "Concealed (Apache OFBiz version hidden)",
                "source": f"HTTP GET {path} (Apache OFBiz interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"Apache OFBiz detected on port {port} ({path}), but exact release version is concealed. "
                    f"Verify that the deployment is updated to Apache OFBiz 24.09.08 or later."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified Apache OFBiz ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("ofbiz_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Apache OFBiz v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] Apache OFBiz v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-83542 / CVE-2026-82907 confirmed on {target_ip}.\n"
                f"Vulnerable Apache OFBiz instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-83542 / CVE-2026-82907 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an unpatched Apache OFBiz instance (< 24.09.08).\n"
                f"Flaw Overview:\n"
                f"Apache OFBiz prior to 24.09.08 contains a screen descriptor validation flaw (CVE-2026-83542) "
                f"and an ExternalLoginKeysManager session handling flaw (CVE-2026-82907).\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Apache OFBiz immediately to version 24.09.08 or later.\n"
                f"2. Restrict external access to administrative routes (/webtools, /ordermgr, /sfa) behind a reverse proxy or VPN."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "Apache OFBiz active with concealed version."
            details = (
                f"Apache OFBiz detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Apache OFBiz instances on {target_ip} are running versions resistant to CVE-2026-83542:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable Apache OFBiz instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for Apache OFBiz CVE-2026-83542 / CVE-2026-82907."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[8443, 8080, 443, 80],
        help="Ports to inspect (default: 8443 8080 443 80)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-83542 Auditor (Apache OFBiz)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = ApacheOfbizAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-83542!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual Apache OFBiz version verification.\n")
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
