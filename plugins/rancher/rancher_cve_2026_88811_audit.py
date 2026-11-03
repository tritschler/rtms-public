"""
rancher_cve_2026_88811_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints (ports 80, 443, 8080, 8443, 9443) for SUSE Rancher Manager
deployments vulnerable to:
  - CVE-2026-88811 (CVSS 9.1 Critical): Missing filtering in the SUSE Rancher Manager
    meta-proxy causing passed-in Rancher credentials to be leaked to external cloud providers.
  - CVE-2026-94290 (CVSS 9.1 Critical): Insufficient restriction on Fleet Cluster kubeconfig
    secret references allowing cross-namespace cluster privilege escalation.

CVSS Score: 9.1 (Critical) - CWE-200 / CWE-269
Affected Versions:
  - SUSE Rancher 2.15.0 through 2.15.3 (Fixed in 2.15.4+)
  - SUSE Rancher 2.14.0 through 2.14.7 (Fixed in 2.14.8+)
  - SUSE Rancher 2.13.0 through 2.13.11 (Fixed in 2.13.12+)
  - Legacy SUSE Rancher < 2.13.0

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
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/HTTPS Rancher ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_RANCHER_PORTS = [80, 443, 8080, 8443, 9443]
SSL_PORTS = {443, 8443, 9443, 4433, 10443}


def parse_rancher_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts SUSE Rancher semantic version (major, minor, patch, raw_str) from:
      1. /rancherversion JSON: {"Version":"v2.15.2","GitCommit":"...","RancherPrime":"..."}
      2. /v3/settings/server-version JSON: {"id":"server-version","value":"v2.14.6"}
      3. Dashboard HTML / JS metadata: rancherVersion: "2.13.9"
    """
    if not text:
        return None

    patterns = [
        r'"Version"\s*:\s*"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-[a-zA-Z0-9._-]+)?"',
        r'"value"\s*:\s*"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-[a-zA-Z0-9._-]+)?"',
        r'rancher[-_\s]*version[\'":\s=]+v?([0-9]+)\.([0-9]+)\.([0-9]+)',
        r'\bRancher\s+v?([0-9]+)\.([0-9]+)\.([0-9]+)\b',
        r'^v?([0-9]+)\.([0-9]+)\.([0-9]+)$',
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            raw_ver = f"{major}.{minor}.{patch}"
            return major, minor, patch, raw_ver

    return None


def is_rancher_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates SUSE Rancher version tuple against CVE-2026-88811 and CVE-2026-94290:
      - 2.15.0 <= v <= 2.15.3 -> Vulnerable (Requires >= 2.15.4)
      - 2.14.0 <= v <= 2.14.7 -> Vulnerable (Requires >= 2.14.8)
      - 2.13.0 <= v <= 2.13.11 -> Vulnerable (Requires >= 2.13.12)
      - < 2.13.0 -> Vulnerable / unsupported branch
    """
    ver_str = f"{major}.{minor}.{patch}"

    if major < 2 or (major == 2 and minor < 13):
        return True, (
            f"SUSE Rancher v{ver_str} belongs to a legacy branch (< 2.13.0) vulnerable to "
            f"CVE-2026-88811 (meta-proxy credential leak) and CVE-2026-94290 (Fleet kubeconfig escalation). "
            f"Requires upgrade to >= 2.13.12, >= 2.14.8, or >= 2.15.4."
        )

    if major == 2 and minor == 13:
        if patch <= 11:
            return True, (
                f"SUSE Rancher v{ver_str} is vulnerable to CVE-2026-88811 & CVE-2026-94290 "
                f"(affected: 2.13.0 - 2.13.11; requires >= 2.13.12)."
            )
        return False, f"SUSE Rancher v{ver_str} is patched in the 2.13.x train (>= 2.13.12)."

    if major == 2 and minor == 14:
        if patch <= 7:
            return True, (
                f"SUSE Rancher v{ver_str} is vulnerable to CVE-2026-88811 & CVE-2026-94290 "
                f"(affected: 2.14.0 - 2.14.7; requires >= 2.14.8)."
            )
        return False, f"SUSE Rancher v{ver_str} is patched in the 2.14.x train (>= 2.14.8)."

    if major == 2 and minor == 15:
        if patch <= 3:
            return True, (
                f"SUSE Rancher v{ver_str} is vulnerable to CVE-2026-88811 & CVE-2026-94290 "
                f"(affected: 2.15.0 - 2.15.3; requires >= 2.15.4)."
            )
        return False, f"SUSE Rancher v{ver_str} is patched in the 2.15.x train (>= 2.15.4)."

    return False, f"SUSE Rancher v{ver_str} is running a release >= 2.16.0 unaffected by CVE-2026-88811."


class RancherSecurityAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: SUSE Rancher Manager Meta-Proxy & Fleet Audit (CVE-2026-88811 / CVE-2026-94290).
    Performs safe, non-destructive HTTP/HTTPS inspection of SUSE Rancher Manager endpoints.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "SUSE Rancher Manager Meta-Proxy & Fleet Audit (CVE-2026-88811)",
            "description": "Audits HTTP/HTTPS endpoints (ports 80, 443, 8080, 8443, 9443) for SUSE Rancher Manager (2.13.0-2.13.11, 2.14.0-2.14.7, 2.15.0-2.15.3) vulnerable to meta-proxy credential leakage (CVE-2026-88811) and Fleet kubeconfig escalation (CVE-2026-94290).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-88811",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_RANCHER_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers HTTP/HTTPS or Kubernetes/Rancher management ports on the target host.
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
                    or "https" in s_name
                    or "rancher" in s_name
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
        path: str = "/rancherversion",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect SUSE Rancher version and headers.
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-88811)",
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
        Probes standard SUSE Rancher endpoints (/rancherversion, /v3/settings/server-version, /dashboard/auth/login).
        """
        candidate_paths = [
            "/rancherversion",
            "/v3/settings/server-version",
            "/v1/management.cattle.io.settings/server-version",
            "/dashboard/auth/login",
        ]

        for path in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            body_lower = body.lower()

            has_cattle_hdr = any("cattle" in k or "rancher" in k for k in headers.keys())
            is_rancher = (
                has_cattle_hdr
                or "rancherprime" in body_lower
                or '"gitcommit"' in body_lower
                or '"server-version"' in body_lower
                or "management.cattle.io" in body_lower
                or "rancher-dashboard" in body_lower
                or "<title>rancher</title>" in body_lower
            )

            if not is_rancher:
                continue

            ver_info = parse_rancher_version(body)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_rancher_version_vulnerable(major, minor, patch)
                return {
                    "port": port,
                    "rancher_detected": True,
                    "version": ver_str,
                    "source": f"HTTP GET {path}",
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

            return {
                "port": port,
                "rancher_detected": True,
                "version": "Concealed (version endpoint restricted)",
                "source": f"HTTP GET {path} (Rancher Cattle API / Dashboard signature)",
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    f"SUSE Rancher Manager detected on port {port} ({path}), but version metadata "
                    f"requires authentication. Verify that Rancher runs >= 2.13.12, >= 2.14.8, or >= 2.15.4."
                )
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified Rancher ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("rancher_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] SUSE Rancher v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] SUSE Rancher v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-88811 & CVE-2026-94290 confirmed on {target_ip}.\n"
                f"Vulnerable SUSE Rancher Manager instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-88811 & CVE-2026-94290 - CVSS 9.1):\n"
                f"The target host {target_ip} runs a vulnerable SUSE Rancher Manager version.\n"
                f"Flaw Overview:\n"
                f"1. CVE-2026-88811 (CVSS 9.1): Missing header/credential filtering in the SUSE Rancher Manager "
                f"meta-proxy (/meta/proxy) causes passed-in Rancher credentials and tokens to be leaked to external "
                f"cloud provider endpoints.\n"
                f"2. CVE-2026-94290 (CVSS 9.1): Insufficient restriction on kubeconfig secret references in Rancher "
                f"Fleet Cluster objects allows cross-namespace privilege escalation and unauthorized cluster takeover.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade SUSE Rancher Manager to patched versions: >= 2.15.4, >= 2.14.8, or >= 2.13.12.\n"
                f"2. Restrict external access to the Rancher management plane (/meta/proxy, /v3, /v1) via firewall/VPN."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "SUSE Rancher Manager active with restricted version metadata."
            details = (
                f"SUSE Rancher Manager detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: SUSE Rancher Manager instances on {target_ip} are running patched versions "
                f"resistant to CVE-2026-88811 and CVE-2026-94290:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable SUSE Rancher Manager instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit HTTP/HTTPS endpoints for SUSE Rancher Manager vulnerabilities (CVE-2026-88811 / CVE-2026-94290)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 8080, 8443, 9443],
        help="Ports to inspect (default: 80 443 8080 8443 9443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-88811 Auditor (SUSE Rancher)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = RancherSecurityAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-88811 / CVE-2026-94290!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual patch verification.\n")
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
