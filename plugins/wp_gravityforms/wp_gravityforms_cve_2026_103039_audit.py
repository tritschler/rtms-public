"""
wp_gravityforms_cve_2026_103039_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints for WordPress installations running the Gravity Forms
plugin (versions <= 3.1.2) vulnerable to Unauthenticated PHP Object Injection
via Post Custom Field (List input type) in GFFormsModel::create_post() (CVE-2026-103039).

CVSS Score: 9.8 (Critical) - CWE-502 (Deserialization of Untrusted Data)
Affected Components: WordPress Gravity Forms Plugin (all versions <= 3.1.2).
Fixed in: Gravity Forms 3.1.3+.

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
                return self.format_result("Skipped", details="Requirements not met (no target HTTP/HTTPS services found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

# Common ports serving HTTP/HTTPS WordPress applications
DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8088, 8888, 9443]
SSL_PORTS = {443, 8443, 9443, 4433, 10443}

# Patched version threshold: Gravity Forms 3.1.3+ fixes CVE-2026-103039 (<= 3.1.2 is vulnerable)
MAX_VULNERABLE_VERSION = (3, 1, 2)
MIN_PATCHED_VERSION = (3, 1, 3)


def parse_gravityforms_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Gravity Forms semantic version (major, minor, patch, raw_str) from:
      - WordPress asset query strings: /wp-content/plugins/gravityforms/...?ver=3.1.2
      - Plugin changelog / readme headers: 'Stable tag: 3.1.2', '### 3.1.2', 'Version: 3.1.2'
      - Raw version strings: '3.1.2', '2.8.17.1'
    """
    if not text:
        return None

    patterns = [
        # 1. Asset URL with ?ver=X.Y.Z inside gravityforms plugin path
        r"/wp-content/plugins/gravityforms/[^\"'\s>]+?\?ver=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?",
        # 2. Stable tag or Version header in readme.txt / changelog.txt / CSS-JS banner
        r"(?:Stable\s+tag|Version|\*+\s*Version)\s*:\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?",
        # 3. Markdown changelog heading: ### 3.1.2 | 2026-...
        r"###\s+([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?\s*(?:\||-|$)",
        # 4. Direct version string when called on an isolated version token
        r"^v?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            subpatch = match.group(4)
            raw_ver = f"{major}.{minor}.{patch}" + (f".{subpatch}" if subpatch is not None else "")
            return major, minor, patch, raw_ver

    return None


def is_gravityforms_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Gravity Forms version tuple (major, minor, patch) is vulnerable
    to CVE-2026-103039 (all versions <= 3.1.2 are vulnerable; fixed in 3.1.3+).
    Returns (is_vulnerable, explanation).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if ver_tuple <= MAX_VULNERABLE_VERSION:
        return True, (
            f"Gravity Forms {ver_str} is vulnerable to CVE-2026-103039 "
            f"(affected: <= 3.1.2; requires upgrade to >= 3.1.3). "
            f"GFFormsModel::create_post() passes Post Custom Field (List) values to unrestricted "
            f"maybe_unserialize() instead of GFCommon::maybe_unserialize(allowed_classes => false)."
        )

    return False, (
        f"Gravity Forms {ver_str} is patched against CVE-2026-103039 "
        f"(running >= 3.1.3 with hardened GFCommon::maybe_unserialize())."
    )


class WPGravityFormsAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: WordPress Gravity Forms PHP Object Injection Audit (CVE-2026-103039).
    Performs safe, non-destructive HTTP/HTTPS fingerprinting to detect exposed WordPress
    installations running vulnerable Gravity Forms versions (<= 3.1.2).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "WordPress Gravity Forms PHP Object Injection Audit (CVE-2026-103039)",
            "description": "Audits HTTP/HTTPS endpoints for WordPress installations running Gravity Forms <= 3.1.2 vulnerable to PHP Object Injection via Post Custom Field (List input type) in GFFormsModel::create_post() (CVE-2026-103039).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-103039",
            "version": "1.0.0"
        }
        self.target_ports = DEFAULT_WEB_PORTS.copy()
        self.ssl_ports = sorted(list(SSL_PORTS))
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Filters and registers web, HTTP, HTTPS, or WordPress service ports on the target host.
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
                    or "web" in s_name
                    or "wordpress" in s_name
                    or "ssl" in s_name
                    or "tls" in s_name
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
        timeout: float = 4.0
    ) -> Optional[Dict[str, Any]]:
        """
        Safely performs a read-only HTTP/HTTPS GET request and returns status, headers, and body snippet.
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-103039)",
                "Accept": "text/html,text/plain,application/xhtml+xml,*/*",
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
        Probes a target web port for WordPress and Gravity Forms plugin presence and version.
        """
        # 1. Probe root page to check for embedded Gravity Forms assets or WordPress markers
        root_probe = self.probe_http_endpoint(target_ip, port, path="/", timeout=timeout)
        if not root_probe:
            return None

        root_body = root_probe.get("body_snippet", "")
        root_headers = root_probe.get("headers", {})

        # Check if Gravity Forms asset version is directly exposed in homepage HTML
        gf_ver_from_html = parse_gravityforms_version(root_body)
        if gf_ver_from_html:
            major, minor, patch, ver_str = gf_ver_from_html
            is_vuln, reason = is_gravityforms_version_vulnerable(major, minor, patch)
            return {
                "port": port,
                "gf_detected": True,
                "version": ver_str,
                "source": "HTML asset reference (/wp-content/plugins/gravityforms/...?ver=)",
                "is_vulnerable": is_vuln,
                "reason": reason
            }

        gf_marker_in_html = (
            "/wp-content/plugins/gravityforms" in root_body.lower()
            or "gform_wrapper" in root_body.lower()
            or "gf_global" in root_body.lower()
        )

        wp_marker_detected = (
            gf_marker_in_html
            or "/wp-content/" in root_body.lower()
            or "/wp-includes/" in root_body.lower()
            or "wp-json" in root_body.lower()
            or "wordpress" in root_body.lower()
            or "x-pingback" in root_headers
            or "wp-json" in root_headers.get("link", "").lower()
        )

        # 2. Probe Gravity Forms static metadata / changelog endpoints
        candidate_paths = [
            ("/wp-content/plugins/gravityforms/change_log.txt", "Gravity Forms change_log.txt"),
            ("/wp-content/plugins/gravityforms/changelog.txt", "Gravity Forms changelog.txt"),
            ("/wp-content/plugins/gravityforms/readme.txt", "Gravity Forms readme.txt"),
            ("/wp-content/plugins/gravityforms/css/formsmain.min.css", "Gravity Forms formsmain.min.css"),
            ("/wp-content/plugins/gravityforms/js/gravityforms.min.js", "Gravity Forms gravityforms.min.js"),
        ]

        gf_asset_confirmed = gf_marker_in_html
        gf_confirmed_source = "Homepage HTML markers (gform_wrapper / /wp-content/plugins/gravityforms/)"

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe or probe.get("status_code") != 200:
                continue

            body = probe.get("body_snippet", "")
            if not body:
                continue

            # Verify response is genuinely a Gravity Forms file (and not a generic HTML 200 soft-404)
            body_lower = body.lower()
            is_genuine_gf_file = (
                "gravity forms" in body_lower
                or "gravityforms" in body_lower
                or "gform" in body_lower
                or "rocketgenius" in body_lower
            )
            if not is_genuine_gf_file:
                continue

            gf_asset_confirmed = True
            gf_confirmed_source = f"HTTP 200 on {path} ({source_label})"

            ver_info = parse_gravityforms_version(body)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_gravityforms_version_vulnerable(major, minor, patch)
                return {
                    "port": port,
                    "gf_detected": True,
                    "version": ver_str,
                    "source": source_label,
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

        # 3. If Gravity Forms is confirmed present but exact version string is stripped/concealed
        if gf_asset_confirmed:
            return {
                "port": port,
                "gf_detected": True,
                "version": "Concealed (version query string / changelog hidden)",
                "source": gf_confirmed_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "WordPress Gravity Forms plugin is active on this endpoint, but its exact version "
                    "string is concealed. Manually verify in WP-Admin that Gravity Forms is updated to >= 3.1.3 "
                    "to protect against CVE-2026-103039."
                )
            }

        # 4. WordPress detected without Gravity Forms
        if wp_marker_detected:
            return {
                "port": port,
                "gf_detected": False,
                "wp_detected": True,
                "is_vulnerable": False,
                "reason": "WordPress installation detected, but Gravity Forms plugin was not found."
            }

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes targeted security audit across all identified web ports on target_ip.
        """
        ports_to_scan = self.discovered_ports if self.discovered_ports else self.target_ports
        vulnerable_findings: List[str] = []
        safe_findings: List[str] = []
        concealed_findings: List[str] = []

        for port in ports_to_scan:
            result = self.inspect_target_port(target_ip, port)
            if not result or not result.get("gf_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Gravity Forms {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Gravity Forms {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-103039 confirmed on {target_ip}.\n"
                f"Vulnerable WordPress Gravity Forms endpoints detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-103039 - CVSS 9.8):\n"
                f"The target host {target_ip} runs a vulnerable version of the WordPress Gravity Forms plugin (<= 3.1.2).\n"
                f"Flaw Overview: Gravity Forms is vulnerable to PHP Object Injection via a Post Custom Field whose "
                f"input type is 'List'. GFFormsModel::create_post() passes the submitted value to WordPress's "
                f"unrestricted global maybe_unserialize() instead of the hardened GFCommon::maybe_unserialize() "
                f"(which enforces allowed_classes => false). Unauthenticated attackers can inject arbitrary PHP objects "
                f"to achieve remote code execution (RCE), arbitrary file deletion, or sensitive data exposure.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately update the Gravity Forms WordPress plugin to version 3.1.3 or later.\n"
                f"2. Audit public forms utilizing 'Post Custom Field' with the 'List' input type.\n"
                f"3. Restrict access to /wp-content/plugins/gravityforms/ metadata files via WAF/web server rules."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "WordPress Gravity Forms active with concealed version metadata."
            details = (
                f"Gravity Forms detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings) + "\n\n"
                f"Please verify in WordPress Admin > Plugins that Gravity Forms is updated to version 3.1.3+."
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: WordPress Gravity Forms instances on {target_ip} are running patched versions "
                f"(>= 3.1.3) resistant to CVE-2026-103039:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable WordPress Gravity Forms installations detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit web endpoints for WordPress Gravity Forms PHP Object Injection (CVE-2026-103039)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 8080, 8443],
        help="Ports to inspect (default: 80 443 8080 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="HTTP probe timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 76)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-103039 Auditor (Gravity Forms)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = WPGravityFormsAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-103039!\n")
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
