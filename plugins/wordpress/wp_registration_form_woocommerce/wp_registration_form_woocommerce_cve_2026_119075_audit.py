"""
wp_registration_form_woocommerce_cve_2026_119075_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits HTTP/HTTPS endpoints for WordPress installations running the Registration
Form for WooCommerce plugin by ThemeGrill (versions <= 1.1.4) affected by an
unauthenticated privilege escalation vulnerability in
FormHandler::validate_checkout_fields() (CVE-2026-119075).

CVSS Score: 9.8 (Critical) - CWE-269 (Improper Privilege Management)
Affected Components: WordPress Registration Form for WooCommerce Plugin (<= 1.1.4).
Fixed in: Registration Form for WooCommerce 1.1.5+.

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

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8088, 8888, 9443]
SSL_PORTS = {443, 8443, 9443, 4433, 10443}

# Patched version threshold: 1.1.5+ fixes CVE-2026-119075 (<= 1.1.4 is vulnerable)
MAX_VULNERABLE_VERSION = (1, 1, 4)
MIN_PATCHED_VERSION = (1, 1, 5)


def parse_registration_form_wc_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extracts Registration Form for WooCommerce semantic version
    (major, minor, patch, raw_str) from:
      - WordPress asset query strings: /wp-content/plugins/registration-form-for-woocommerce/...?ver=1.1.4
      - Plugin changelog / readme headers: 'Stable tag: 1.1.4', '= 1.1.4 =', 'Version: 1.1.4'
      - Raw version strings: '1.1.4'
    """
    if not text:
        return None

    patterns = [
        # 1. Asset URL with ?ver=X.Y.Z inside plugin directory
        r"/wp-content/plugins/(?:registration-form-for-woocommerce|tgwcfb)/[^\"'\s>]+?\?ver=([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?",
        # 2. Stable tag or Version header in readme.txt / changelog.txt / CSS-JS banner
        r"(?:Stable\s+tag|Version|\*+\s*Version)\s*:\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?",
        # 3. Markdown or WP readme changelog heading: = 1.1.4 = or ### 1.1.4
        r"(?:=+|###)\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?\s*(?:=+|\||-|$)",
        # 4. Direct version token
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


def is_registration_form_wc_version_vulnerable(major: int, minor: int, patch: int) -> Tuple[bool, str]:
    """
    Evaluates whether a Registration Form for WooCommerce version tuple
    (major, minor, patch) is vulnerable to CVE-2026-119075 (<= 1.1.4 is vulnerable; fixed in 1.1.5+).
    """
    ver_tuple = (major, minor, patch)
    ver_str = f"{major}.{minor}.{patch}"

    if ver_tuple <= MAX_VULNERABLE_VERSION:
        return True, (
            f"Registration Form for WooCommerce {ver_str} is vulnerable to CVE-2026-119075 "
            f"(affected: <= 1.1.4; requires upgrade to >= 1.1.5). "
            f"FormHandler::validate_checkout_fields() does not enforce the allowed user-role "
            f"allow-list during WooCommerce checkout account registration."
        )

    return False, (
        f"Registration Form for WooCommerce {ver_str} is patched against CVE-2026-119075 "
        f"(running >= 1.1.5)."
    )


class WPRegistrationFormWooCommerceAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: WordPress Registration Form for WooCommerce Privilege Escalation Audit (CVE-2026-119075).
    Performs safe, non-destructive HTTP/HTTPS fingerprinting to detect exposed WordPress
    installations running vulnerable versions of the plugin (<= 1.1.4).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "WordPress Registration Form for WooCommerce Privilege Escalation Audit (CVE-2026-119075)",
            "description": "Audits HTTP/HTTPS endpoints for WordPress installations running Registration Form for WooCommerce <= 1.1.4 affected by unauthenticated privilege escalation in FormHandler::validate_checkout_fields() (CVE-2026-119075).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-119075",
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
                "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-119075)",
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
        Probes a target web port for WordPress and Registration Form for WooCommerce presence and version.
        """
        root_probe = self.probe_http_endpoint(target_ip, port, path="/", timeout=timeout)
        if not root_probe:
            return None

        root_body = root_probe.get("body_snippet", "")
        root_headers = root_probe.get("headers", {})

        # 1. Check if plugin asset version is directly exposed in homepage HTML
        ver_from_html = parse_registration_form_wc_version(root_body)
        if ver_from_html and (
            "registration-form-for-woocommerce" in root_body.lower()
            or "tgwcfb" in root_body.lower()
        ):
            major, minor, patch, ver_str = ver_from_html
            is_vuln, reason = is_registration_form_wc_version_vulnerable(major, minor, patch)
            return {
                "port": port,
                "plugin_detected": True,
                "version": ver_str,
                "source": "HTML asset reference (/wp-content/plugins/registration-form-for-woocommerce/...?ver=)",
                "is_vulnerable": is_vuln,
                "reason": reason
            }

        plugin_marker_in_html = (
            "/wp-content/plugins/registration-form-for-woocommerce" in root_body.lower()
            or "tgwcfb" in root_body.lower()
        )

        wp_marker_detected = (
            plugin_marker_in_html
            or "/wp-content/" in root_body.lower()
            or "/wp-includes/" in root_body.lower()
            or "wp-json" in root_body.lower()
            or "wordpress" in root_body.lower()
            or "x-pingback" in root_headers
            or "wp-json" in root_headers.get("link", "").lower()
        )

        # 2. Probe static readme / changelog endpoints
        candidate_paths = [
            ("/wp-content/plugins/registration-form-for-woocommerce/readme.txt", "Plugin readme.txt"),
            ("/wp-content/plugins/registration-form-for-woocommerce/changelog.txt", "Plugin changelog.txt"),
            ("/wp-content/plugins/registration-form-for-woocommerce/assets/css/frontend.css", "Plugin frontend.css"),
            ("/wp-content/plugins/registration-form-for-woocommerce/assets/js/frontend.js", "Plugin frontend.js"),
        ]

        asset_confirmed = plugin_marker_in_html
        confirmed_source = "Homepage HTML markers (tgwcfb / registration-form-for-woocommerce)"

        for path, source_label in candidate_paths:
            probe = self.probe_http_endpoint(target_ip, port, path=path, timeout=timeout)
            if not probe or probe.get("status_code") != 200:
                continue

            body = probe.get("body_snippet", "")
            if not body:
                continue

            body_lower = body.lower()
            is_genuine_file = (
                "registration form for woocommerce" in body_lower
                or "themegrill" in body_lower
                or "tgwcfb" in body_lower
            )
            if not is_genuine_file:
                continue

            asset_confirmed = True
            confirmed_source = f"HTTP 200 on {path} ({source_label})"

            ver_info = parse_registration_form_wc_version(body)
            if ver_info:
                major, minor, patch, ver_str = ver_info
                is_vuln, reason = is_registration_form_wc_version_vulnerable(major, minor, patch)
                return {
                    "port": port,
                    "plugin_detected": True,
                    "version": ver_str,
                    "source": source_label,
                    "is_vulnerable": is_vuln,
                    "reason": reason
                }

        if asset_confirmed:
            return {
                "port": port,
                "plugin_detected": True,
                "version": "Concealed (version query string / readme hidden)",
                "source": confirmed_source,
                "is_vulnerable": False,
                "concealed": True,
                "reason": (
                    "WordPress Registration Form for WooCommerce plugin is active on this endpoint, "
                    "but its exact version string is concealed. Manually verify in WP-Admin that the plugin is "
                    "updated to >= 1.1.5 to protect against CVE-2026-119075."
                )
            }

        if wp_marker_detected:
            return {
                "port": port,
                "plugin_detected": False,
                "wp_detected": True,
                "is_vulnerable": False,
                "reason": "WordPress installation detected, but Registration Form for WooCommerce was not found."
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
            if not result or not result.get("plugin_detected"):
                continue

            port_label = f"Port {port}"
            if result.get("is_vulnerable"):
                vulnerable_findings.append(
                    f"- [{port_label}] Registration Form for WooCommerce {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )
            elif result.get("concealed"):
                concealed_findings.append(
                    f"- [{port_label}] {result.get('reason')} (Source: {result.get('source')})"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] Registration Form for WooCommerce {result.get('version')} detected via {result.get('source')}. "
                    f"Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-119075 confirmed on {target_ip}.\n"
                f"Vulnerable WordPress Registration Form for WooCommerce endpoints detected:\n" + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-119075 - CVSS 9.8):\n"
                f"The target host {target_ip} runs a vulnerable version of the WordPress Registration Form "
                f"for WooCommerce plugin (<= 1.1.4).\n"
                f"Flaw Overview: FormHandler::validate_checkout_fields() fails to validate submitted user_roles "
                f"parameters against the configured role allow-list during WooCommerce checkout registration, "
                f"allowing unauthenticated users to assign themselves the Administrator role upon account creation.\n\n"
                f"Vulnerable Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Immediately update Registration Form for WooCommerce to version 1.1.5 or later.\n"
                f"2. Audit existing WordPress administrator accounts for unauthorized registrations.\n"
                f"3. Restrict public access to plugin readme.txt and changelog.txt files."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if concealed_findings and not safe_findings:
            proof = "WordPress Registration Form for WooCommerce active with concealed version metadata."
            details = (
                f"Registration Form for WooCommerce detected on {target_ip} with concealed version metadata:\n"
                + "\n".join(concealed_findings) + "\n\n"
                f"Please verify in WordPress Admin > Plugins that the plugin is updated to version 1.1.5+."
            )
            return self.format_result("Warning", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: WordPress Registration Form for WooCommerce instances on {target_ip} are running patched versions "
                f"(>= 1.1.5) resistant to CVE-2026-119075:\n" + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No vulnerable WordPress Registration Form for WooCommerce installations detected on target ports."
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Audit web endpoints for WordPress Registration Form for WooCommerce Privilege Escalation (CVE-2026-119075)."
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
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-119075 Auditor (Registration Form WC)")
    print(f"    Target:  {args.target}")
    print(f"    Ports:   {', '.join(str(p) for p in args.ports)}")
    print("=" * 76 + "\n")

    plugin = WPRegistrationFormWooCommerceAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)
    status = result.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-119075!\n")
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
