"""
freeswitch_cve_2026_116779_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits SIP and HTTP/WebSocket endpoints (ports 5060, 5061, 5080, 7443, 8080)
for SignalWire FreeSWITCH instances (versions prior to 1.11.3) affected by
CVE-2026-116779, CVE-2026-116785, and CVE-2026-116790.

CVSS Score: 9.8 (Critical) - CWE-78 / CWE-190 / CWE-345
Affected Components: FreeSWITCH versions < 1.11.3.
Fixed in: FreeSWITCH 1.11.3+.

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
                return self.format_result("Skipped", details="Requirements not met (no target FreeSWITCH ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Standard FreeSWITCH SIP and HTTP/WSS ports
DEFAULT_FREESWITCH_PORTS = [5060, 5061, 5080, 7443, 8080]
SIP_PORTS = {5060, 5061, 5080}
SSL_PORTS = {5061, 7443, 443, 8443}
FIXED_VERSION = (1, 11, 3)


def parse_freeswitch_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts FreeSWITCH version (major, minor, patch, raw_str) from:
      1. SIP User-Agent / Server header: FreeSWITCH-mod_sofia/1.10.11-release~64bit
      2. Banner or HTTP header: FreeSWITCH/1.11.1, FreeSWITCH Version 1.10.12
      3. Plain version string: 1.11.2
    """
    if not text:
        return None

    patterns = [
        r'FreeSWITCH(?:-mod_sofia)?[/\s:]+(?:Version\s+)?v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[\.\-~][0-9a-zA-Z~_\-]+)?',
        r'"version"\s*:\s*"v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:[\.\-~][0-9a-zA-Z~_\-]+)?"',
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


def is_freeswitch_vulnerable(major: int, minor: int, patch: int, raw_str: str = "") -> Tuple[bool, str]:
    """
    Evaluates FreeSWITCH version against CVE-2026-116779 / CVE-2026-116785 / CVE-2026-116790
    (versions < 1.11.3 are vulnerable).
    """
    ver_tuple = (major, minor, patch)
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if ver_tuple < FIXED_VERSION:
        return True, (
            f"FreeSWITCH {ver_display} is affected by CVE-2026-116779 (CVSS 9.8 SIP MESSAGE protocol selector flaw), "
            f"CVE-2026-116785 (WebSocket frame length handling), and CVE-2026-116790 (ICE STUN integrity validation); "
            f"fixed in 1.11.3."
        )

    return False, (
        f"FreeSWITCH {ver_display} is not affected by CVE-2026-116779 "
        f"(patched in >= 1.11.3)."
    )


class FreeSwitchAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: FreeSWITCH Telecom Stack Version Audit (CVE-2026-116779).
    Performs safe, read-only SIP OPTIONS and HTTP header banner inspection.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "FreeSWITCH SIP & WebRTC Stack Version Audit (CVE-2026-116779)",
            "description": "Audits SIP/HTTP endpoints (ports 5060, 5061, 5080, 7443, 8080) for FreeSWITCH instances (< 1.11.3) affected by CVE-2026-116779, CVE-2026-116785, and CVE-2026-116790.",
            "severity": "CRITICAL",
            "cve": "CVE-2026-116779",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_FREESWITCH_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers SIP, WebRTC, or HTTP ports on the target host.
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
                    or "sip" in s_name
                    or "freeswitch" in s_name
                    or "voip" in s_name
                    or "http" in s_name
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

    def probe_sip_options(
        self,
        target_ip: str,
        port: int,
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Sends a standard, non-intrusive SIP OPTIONS query over TCP (or TLS on 5061) to read the User-Agent / Server header.
        """
        use_tls = port == 5061
        sock = None

        sip_request = (
            f"OPTIONS sip:{target_ip}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/{'TLS' if use_tls else 'TCP'} 127.0.0.1:5060;branch=z9hG4bK-rtms-audit\r\n"
            f"Max-Forwards: 70\r\n"
            f"To: <sip:{target_ip}:{port}>\r\n"
            f"From: <sip:rtms-audit@127.0.0.1>;tag=rtms100\r\n"
            f"Call-ID: rtms-cve-2026-116779-audit@{target_ip}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"User-Agent: RTMS-Security-Audit/1.0\r\n"
            f"Accept: application/sdp\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode("utf-8")

        try:
            raw_sock = socket.create_connection((target_ip, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw_sock, server_hostname=target_ip)
            else:
                sock = raw_sock

            sock.sendall(sip_request)
            data = sock.recv(8192).decode("utf-8", errors="replace")
            if not data:
                return None

            headers: Dict[str, str] = {}
            for line in data.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            return {
                "port": port,
                "protocol": "SIP/TLS" if use_tls else "SIP/TCP",
                "raw_response": data[:4096],
                "headers": headers
            }
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        except Exception as e:
            logger.debug(f"SIP OPTIONS probe failed on {target_ip}:{port}: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def probe_http_endpoint(
        self,
        target_ip: str,
        port: int,
        path: str = "/",
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Performs a read-only HTTP/HTTPS GET request to inspect FreeSWITCH HTTP/WebSocket server headers.
        """
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-116779)",
                "Accept": "*/*",
                "Connection": "close"
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
                "body_snippet": raw_body[:8192]
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
        Inspects a target port via SIP OPTIONS (for SIP ports) or HTTP GET to identify FreeSWITCH and its version.
        """
        # 1. Try SIP OPTIONS first on SIP ports
        if port in SIP_PORTS or port not in (80, 443, 7443, 8080):
            sip_res = self.probe_sip_options(target_ip, port, timeout=timeout)
            if sip_res:
                headers = sip_res.get("headers", {})
                ua_banner = headers.get("user-agent", "") or headers.get("server", "")
                raw_resp = sip_res.get("raw_response", "")

                if "freeswitch" in ua_banner.lower() or "freeswitch" in raw_resp.lower():
                    ver_info = parse_freeswitch_version(ua_banner) or parse_freeswitch_version(raw_resp)
                    if ver_info:
                        major, minor, patch, raw_str = ver_info
                        is_vuln, reason = is_freeswitch_vulnerable(major, minor, patch, raw_str)
                        return {
                            "port": port,
                            "freeswitch_detected": True,
                            "version": raw_str,
                            "source": f"{sip_res.get('protocol', 'SIP')} OPTIONS ({ua_banner or 'banner'})",
                            "is_vulnerable": is_vuln,
                            "reason": reason
                        }

                    return {
                        "port": port,
                        "freeswitch_detected": True,
                        "version": "Concealed (FreeSWITCH version hidden)",
                        "source": f"{sip_res.get('protocol', 'SIP')} OPTIONS",
                        "is_vulnerable": False,
                        "concealed": True,
                        "reason": (
                            f"FreeSWITCH detected on port {port} via SIP OPTIONS, but exact version is concealed. "
                            f"Verify via fs_cli ('version') that FreeSWITCH is updated to 1.11.3 or later."
                        )
                    }

        # 2. Try HTTP/HTTPS probe
        http_res = self.probe_http_endpoint(target_ip, port, path="/", timeout=timeout)
        if http_res:
            headers = http_res.get("headers", {})
            server_hdr = headers.get("server", "")
            body = http_res.get("body_snippet", "")

            if "freeswitch" in server_hdr.lower() or "freeswitch" in body.lower():
                ver_info = parse_freeswitch_version(server_hdr) or parse_freeswitch_version(body)
                if ver_info:
                    major, minor, patch, raw_str = ver_info
                    is_vuln, reason = is_freeswitch_vulnerable(major, minor, patch, raw_str)
                    return {
                        "port": port,
                        "freeswitch_detected": True,
                        "version": raw_str,
                        "source": "HTTP GET /",
                        "is_vulnerable": is_vuln,
                        "reason": reason
                    }

                return {
                    "port": port,
                    "freeswitch_detected": True,
                    "version": "Concealed (FreeSWITCH version hidden)",
                    "source": "HTTP GET /",
                    "is_vulnerable": False,
                    "concealed": True,
                    "reason": (
                        f"FreeSWITCH HTTP interface detected on port {port}, but exact version is concealed. "
                        f"Verify that FreeSWITCH is updated to 1.11.3 or later."
                    )
                }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified FreeSWITCH ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        concealed_findings: List[str] = []
        safe_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("freeswitch_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] FreeSWITCH v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(f"- [{port_label}] {result.get('reason')}")
            else:
                safe_findings.append(
                    f"- [{port_label}] FreeSWITCH v{result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-116779 confirmed on {target_ip}.\n"
                f"Vulnerable FreeSWITCH instances detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-116779 - CVSS 9.8):\n"
                f"The target host {target_ip} runs an unpatched FreeSWITCH instance (< 1.11.3).\n"
                f"Flaw Overview:\n"
                f"FreeSWITCH prior to 1.11.3 contains an inbound SIP MESSAGE protocol selector flaw in "
                f"sofia_presence_handle_sip_i_message() (CVE-2026-116779), a WebSocket payload length flaw "
                f"(CVE-2026-116785), and an ICE STUN message integrity validation flaw (CVE-2026-116790).\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade FreeSWITCH immediately to version 1.11.3 or later.\n"
                f"2. Enable ice_verify_message_integrity=true and restrict inbound SIP MESSAGE handling to trusted authenticated peers."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "FreeSWITCH active with concealed version."
            details = (
                f"FreeSWITCH detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings)
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: FreeSWITCH instances on {target_ip} are running versions resistant to CVE-2026-116779:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable FreeSWITCH instances detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit SIP/HTTP endpoints for FreeSWITCH CVE-2026-116779."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[5060, 5061, 5080, 7443, 8080],
        help="Ports to inspect (default: 5060 5061 5080 7443 8080)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="Probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-116779 Auditor (FreeSWITCH)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = FreeSwitchAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-116779!\n")
        print(result.get("details", ""))
        print("\n" + "=" * 76 + "\n")
        sys.exit(1)
    elif status == "Warning":
        print(f"⚠️  [WARNING] {args.target} requires manual FreeSWITCH version verification.\n")
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
