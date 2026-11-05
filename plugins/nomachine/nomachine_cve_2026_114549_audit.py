"""
nomachine_cve_2026_114549_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 4443, 4080, 443, 8443) for NoMachine
nxwebrunner web services (versions <= 9.7.3) vulnerable to CVE-2026-114549.

CVSS Score: 9.8 (Critical) - CWE-122 (Buffer Copy without Checking Size of Input)
Affected Components: NoMachine (nxwebrunner web service) versions <= 9.7.3.
Fixed in: NoMachine > 9.7.3 (9.7.4+).

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
                return self.format_result("Skipped", details="Requirements not met (no target NoMachine web ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard NoMachine web access ports (4443 HTTPS default, 4080 HTTP default)
DEFAULT_NOMACHINE_PORTS = [4443, 4080, 443, 8443]
SSL_PORTS = {4443, 443, 8443}
MAX_VULNERABLE_VERSION = (9, 7, 3)


def parse_nomachine_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts NoMachine version (major, minor, patch, raw_str) from:
      1. Server header: NoMachine/9.7.3 or nxwebrunner/9.7.3 or nxhtd/9.7.3
      2. Web player HTML title / footer: NoMachine 9.7.3, Version 9.7.3
      3. Asset query parameters or JSON metadata: ?v=9.7.3, "version": "9.7.3"
    """
    if not text:
        return None

    patterns = [
        r'(?:NoMachine|nxwebrunner|nxhtd)[/\s]+v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[_\.\-][0-9a-zA-Z]+)?\b',
        r'(?:NoMachine(?:\s+Web\s+Player)?|Version)[^0-9\r\n]{1,20}v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[_\.\-][0-9a-zA-Z]+)?\b',
        r'\?(?:v|ver|version)=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',
        r'"version"\s*:\s*"v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?"',
        r'^v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch_raw = match.group(3)
            patch = int(patch_raw) if patch_raw is not None else 0
            raw_str = f"{major}.{minor}.{patch_raw}" if patch_raw is not None else f"{major}.{minor}"
            return major, minor, patch, raw_str

    return None


def is_nomachine_vulnerable(major: int, minor: int, patch: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates NoMachine version against CVE-2026-114549 (<= 9.7.3 is vulnerable).
    """
    ver_tuple = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if ver_tuple <= MAX_VULNERABLE_VERSION:
        return True, (
            f"NoMachine {ver_display} is vulnerable to CVE-2026-114549 "
            f"(CVSS 9.8 nxwebrunner web service vulnerability; affected: <= 9.7.3, requires > 9.7.3)."
        )

    return False, (
        f"NoMachine {ver_display} is patched against CVE-2026-114549 "
        f"(running > 9.7.3)."
    )


class NoMachineAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: NoMachine nxwebrunner Web Service Audit (CVE-2026-114549).
    Performs safe, non-destructive HTTP/HTTPS banner and version fingerprinting on port 4443/4080.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "NoMachine nxwebrunner Web Service Audit (CVE-2026-114549)",
            "description": "Audits HTTP/HTTPS endpoints (ports 4443, 4080, 443, 8443) for NoMachine nxwebrunner web services (<= 9.7.3) affected by CVE-2026-114549.",
            "severity": "CRITICAL",
            "cve": "CVE-2026-114549",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_NOMACHINE_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers NoMachine web ports (4443, 4080) or HTTP/HTTPS ports on the target host.
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
                    or "nomachine" in s_name
                    or "nx" in s_name
                    or "http" in s_name
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
        Performs a read-only HTTP/HTTPS GET request to inspect NoMachine web service headers and HTML.
        """
        use_ssl = port in SSL_PORTS or port in (4443, 443, 8443)
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-114549)",
                "Accept": "text/html,application/xhtml+xml,*/*",
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
        Probes standard NoMachine web paths (/, /nxwebplayer) to detect the service and version.
        """
        candidate_paths = ["/", "/nxwebplayer"]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            server_hdr = headers.get("server", "")
            location_hdr = headers.get("location", "").lower()
            server_lower = server_hdr.lower()
            body_lower = body.lower()

            is_nomachine = (
                "nomachine" in server_lower
                or "nxwebrunner" in server_lower
                or "nxhtd" in server_lower
                or "nomachine" in body_lower
                or "nxwebplayer" in body_lower
                or "nxwebrunner" in body_lower
                or "/nxwebplayer" in location_hdr
            )

            if not is_nomachine:
                continue

            ver_info = parse_nomachine_version(server_hdr) or parse_nomachine_version(body)
            if ver_info:
                major, minor, patch, raw_str = ver_info
                is_vuln, reason = is_nomachine_vulnerable(major, minor, patch, raw_str)
                return {
                    "port": port,
                    "nomachine_detected": True,
                    "version": raw_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            if path == "/" and probe.get("status_code") in (301, 302, 303, 307, 308):
                continue

            return {
                "port": port,
                "nomachine_detected": True,
                "version": "Concealed (NoMachine version hidden)",
                "source": f"HTTP GET {path} (NoMachine web interface)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"NoMachine web service (nxwebrunner) detected on port {port} ({path}), but exact "
                    f"version is concealed. Verify via 'nxserver --version' that NoMachine is updated beyond 9.7.3."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified NoMachine web ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("nomachine_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] NoMachine v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] NoMachine v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-114549 confirmed on {target_ip}.\n"
                f"Vulnerable NoMachine web service instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-114549 - CVSS 9.8):\n"
                f"The target host {target_ip} runs a vulnerable NoMachine web service (<= 9.7.3).\n"
                f"Flaw Overview:\n"
                f"A boundary validation flaw in the NoMachine nxwebrunner web service (default TCP port 4443) "
                f"affects versions 9.7.3 and earlier.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately update NoMachine to a patched release (> 9.7.3).\n"
                f"2. If web access is not required, disable the web player service or restrict TCP port 4443/4080 to trusted subnets."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "NoMachine web service active with concealed version."
            details = (
                f"NoMachine web service (nxwebrunner) detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: NoMachine web service instances on {target_ip} are running patched versions "
                f"(> 9.7.3) resistant to CVE-2026-114549:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable NoMachine web service instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for NoMachine CVE-2026-114549."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[4443, 4080, 443, 8443],
        help="Ports to inspect (default: 4443 4080 443 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-114549 Auditor (NoMachine)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = NoMachineAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-114549!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual NoMachine version verification.\n")
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
