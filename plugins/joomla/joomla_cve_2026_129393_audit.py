"""
joomla_cve_2026_129393_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS version verification for Joomla! CMS
deployments via public XML manifests (/administrator/manifests/files/joomla.xml,
/language/en-GB/langmetadata.xml, /language/en-GB/en-GB.xml) and generator metadata
against the November 2026 Joomla! Core Security Advisories (4 Critical CVEs):
  - CVE-2026-129393 (CVSS v4.0: 9.4 Critical):
    Joomla! Core 4.0.0–5.4.10 and 6.0.0–6.2.0 — Inadequate escaping of media custom
    field parameters in generated form XML.
  - CVE-2026-123214 (CVSS v4.0: 9.2 Critical):
    Joomla! Core 4.0.0–5.4.10 and 6.0.0–6.2.0 — Missing authentication in web installer.
  - CVE-2026-126045 (CVSS v4.0: 9.2 Critical):
    Joomla! Core 1.6.0–5.4.10 and 6.0.0–6.2.0 — Local file inclusion via unvalidated
    language request parameter.
  - CVE-2026-127297 (CVSS v4.0: 9.2 Critical):
    Joomla! Core 3.6.0–5.4.10 and 6.0.0–6.2.0 — Race condition in formatted text logger.

Affected Versions:
  - Joomla! CMS 1.6.0 through 5.4.10 (Fixed in 5.4.11+)
  - Joomla! CMS 6.0.0 through 6.2.0 (Fixed in 6.2.1+)

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
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/HTTPS ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_JOOMLA_PORTS = [80, 443, 8080, 8443, 8000, 8888]
SSL_PORTS = {443, 8443, 9443}


def parse_joomla_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts a 3-component Joomla! CMS version tuple (major, minor, patch, raw_str)
    from XML manifests (/administrator/manifests/files/joomla.xml, langmetadata.xml)
    or HTML generator tags / headers.
    """
    if not text:
        return None

    text_lower = text.lower()
    is_joomla_context = (
        "joomla" in text_lower
        or "files_joomla" in text_lower
        or "<extension" in text_lower
        or "<metafile" in text_lower
    )
    if not is_joomla_context:
        return None

    patterns = [
        r"<version>\s*([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})(?:-[A-Za-z0-9._-]+)?\s*</version>",
        r"Joomla!\s*(?:-|\s)*[^\"'<>\n]*?(?:Version\s*|v)?([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})",
        r'"version"\s*:\s*"([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})"',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3))
            ver_str = f"{major}.{minor}.{patch}"
            return major, minor, patch, ver_str

    return None


def is_joomla_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Joomla! CMS version tuple (major, minor, patch) is affected by:
      - CVE-2026-129393 (4.0.0–5.4.10, 6.0.0–6.2.0, CVSS 9.4)
      - CVE-2026-123214 (4.0.0–5.4.10, 6.0.0–6.2.0, CVSS 9.2)
      - CVE-2026-126045 (1.6.0–5.4.10, 6.0.0–6.2.0, CVSS 9.2)
      - CVE-2026-127297 (3.6.0–5.4.10, 6.0.0–6.2.0, CVSS 9.2)
    """
    ver = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if (4, 0, 0) <= ver <= (5, 4, 10):
        return True, (
            f"Joomla! CMS {ver_str} is in the affected 4.0.0–5.4.10 range (< 5.4.11) and is vulnerable to "
            f"CVE-2026-129393 (CVSS 9.4), CVE-2026-123214 (CVSS 9.2), CVE-2026-126045 (CVSS 9.2), "
            f"and CVE-2026-127297 (CVSS 9.2)."
        )

    if (6, 0, 0) <= ver <= (6, 2, 0):
        return True, (
            f"Joomla! CMS {ver_str} is in the affected 6.0.0–6.2.0 range (< 6.2.1) and is vulnerable to "
            f"CVE-2026-129393 (CVSS 9.4), CVE-2026-123214 (CVSS 9.2), CVE-2026-126045 (CVSS 9.2), "
            f"and CVE-2026-127297 (CVSS 9.2)."
        )

    if (3, 6, 0) <= ver < (4, 0, 0):
        return True, (
            f"Joomla! CMS {ver_str} is in the affected 3.6.0–3.x range (< 5.4.11) and is vulnerable to "
            f"CVE-2026-126045 (CVSS 9.2) and CVE-2026-127297 (CVSS 9.2)."
        )

    if (1, 6, 0) <= ver < (3, 6, 0):
        return True, (
            f"Joomla! CMS {ver_str} is in the affected 1.6.0–3.5.x range (< 5.4.11) and is vulnerable to "
            f"CVE-2026-126045 (CVSS 9.2)."
        )

    if (5, 4, 11) <= ver < (6, 0, 0):
        return False, (
            f"Joomla! CMS {ver_str} is patched (>= 5.4.11) against CVE-2026-129393, CVE-2026-123214, "
            f"CVE-2026-126045, and CVE-2026-127297."
        )

    if ver >= (6, 2, 1):
        return False, (
            f"Joomla! CMS {ver_str} is patched (>= 6.2.1) against CVE-2026-129393, CVE-2026-123214, "
            f"CVE-2026-126045, and CVE-2026-127297."
        )

    return False, f"Joomla! CMS {ver_str} is outside the affected ranges for CVE-2026-129393..CVE-2026-127297."


class JoomlaAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Joomla! CMS Multi-CVE Version Compliance Audit
    (CVE-2026-129393, CVE-2026-123214, CVE-2026-126045, CVE-2026-127297).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Joomla! CMS Multi-CVE Version Compliance Audit (CVE-2026-129393 / CVE-2026-123214)",
            "description": (
                "Passive version compliance check for Joomla! CMS instances (1.6.0–5.4.10 and 6.0.0–6.2.0) "
                "against CVE-2026-129393 (CVSS 9.4), CVE-2026-123214 (CVSS 9.2), CVE-2026-126045 (CVSS 9.2), "
                "and CVE-2026-127297 (CVSS 9.2)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-129393",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_JOOMLA_PORTS.copy()
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

                if port in self.target_ports or "http" in s_name or "ssl" in s_name or "joomla" in s_name:
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
        path: str = "/administrator/manifests/files/joomla.xml",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-129393)",
                "Accept": "application/xml,text/xml,text/html,*/*",
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
            ("/administrator/manifests/files/joomla.xml", "Joomla! Core XML manifest (/administrator/manifests/files/joomla.xml)"),
            ("/language/en-GB/langmetadata.xml", "Joomla! language metadata (/language/en-GB/langmetadata.xml)"),
            ("/language/en-GB/en-GB.xml", "Joomla! language XML (/language/en-GB/en-GB.xml)"),
            ("/", "Joomla! web root generator metadata (/)"),
        ]

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe:
                continue

            headers = probe.get("headers", {})
            body = probe.get("body_snippet", "")
            combined = f"{headers}\n{body}"

            ver_info = parse_joomla_version(combined)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_joomla_version_vulnerable(major, minor, patch)
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
                    f"- [{port_label}] Joomla! CMS {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Joomla! CMS {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-129393 / CVE-2026-123214 / CVE-2026-126045 / CVE-2026-127297 affected Joomla! CMS version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-129393, CVE-2026-123214, CVE-2026-126045, CVE-2026-127297 - CVSS 9.4):\n"
                f"The target host {target_ip} runs an unpatched Joomla! CMS instance.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-129393 (4.0.0–5.4.10, 6.0.0–6.2.0, CVSS 9.4): Inadequate escaping of media custom field parameters.\n"
                f"- CVE-2026-123214 (4.0.0–5.4.10, 6.0.0–6.2.0, CVSS 9.2): Missing authentication in web installer.\n"
                f"- CVE-2026-126045 (1.6.0–5.4.10, 6.0.0–6.2.0, CVSS 9.2): Local file inclusion via language parameter.\n"
                f"- CVE-2026-127297 (3.6.0–5.4.10, 6.0.0–6.2.0, CVSS 9.2): Race condition in formatted text logger.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Upgrade Joomla! 5.x/4.x deployments to >= 5.4.11 and Joomla! 6.x deployments to >= 6.2.1.\n"
                f"2. Ensure the /installation directory is removed after deployment and restrict public access to XML manifest paths."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Joomla! CMS instance on {target_ip} meets the minimum patched release (>= 5.4.11 / >= 6.2.1):\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Joomla! CMS services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Joomla! CMS (CVE-2026-129393, CVE-2026-123214, CVE-2026-126045, CVE-2026-127297)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_JOOMLA_PORTS,
        help="Ports to inspect (default: 80 443 8080 8443 8000 8888)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = JoomlaAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs a Joomla! CMS version affected by CVE-2026-129393.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
