"""
mysql_cve_2026_114952_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only version verification for Oracle MySQL Server and
MySQL Cluster (NDB) instances against the November 2026 Oracle Critical Patch Update:
  - CVE-2026-114952 (CVSS 9.1 Critical): Easily exploitable vulnerability in MySQL
    Server and MySQL Cluster (component: Client programs) allowing unauthenticated
    network compromise of critical data confidentiality and integrity.

Affected Versions:
  - Oracle MySQL Server: 8.4.0 through 8.4.13 (fixed in >= 8.4.14),
                         9.7.0 through 9.7.4 (fixed in >= 9.7.5),
                         26.10 (26.10.0, fixed in >= 26.10.1)
  - Oracle MySQL Cluster: 8.0.0 through 8.0.50 (fixed in >= 8.0.51),
                          8.4.0 through 8.4.13 (fixed in >= 8.4.14),
                          9.7.0 through 9.7.4 (fixed in >= 9.7.5),
                          26.10 (26.10.0, fixed in >= 26.10.1)

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import socket
import http.client
import ssl
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
                return self.format_result("Skipped", details="Requirements not met (no target MySQL ports found).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_MYSQL_PORTS = [3306, 33060, 3307, 3308, 8080, 8443]
TCP_GREETING_PORTS = {3306, 33060, 3307, 3308}
SSL_PORTS = {8443, 443}


def parse_mysql_version(text: str) -> Optional[Tuple[int, int, int, bool, str]]:
    """
    Extracts Oracle MySQL Server or MySQL Cluster version tuple
    (major, minor, patch, is_cluster, raw_str) from a MySQL initial handshake
    banner or HTTP/REST server header.
    Excludes MariaDB banners (which contain 'MariaDB').

    Examples:
      - '8.4.12' -> (8, 4, 12, False, '8.4.12')
      - '9.7.3-commercial' -> (9, 7, 3, False, '9.7.3-commercial')
      - '8.0.40-ndb-8.0.40-cluster-gpl' -> (8, 0, 40, True, '8.0.40-ndb-8.0.40-cluster-gpl')
      - '26.10.0' or '26.10' -> (26, 10, 0, False, '26.10')
    """
    if not text or "mariadb" in text.lower():
        return None

    # Check for explicit NDB / MySQL Cluster version string first: e.g. 8.0.40-ndb-8.0.40
    ndb_match = re.search(
        r"\b([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?-ndb-([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})([0-9A-Za-z.\-_]*)",
        text,
        re.IGNORECASE,
    )
    if ndb_match:
        c_maj = int(ndb_match.group(4))
        c_min = int(ndb_match.group(5))
        c_pat = int(ndb_match.group(6))
        return c_maj, c_min, c_pat, True, ndb_match.group(0)

    patterns = [
        r"(?:MySQL(?:\s+Cluster|\s+Server)?[/\s:v\-]+)([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,3}))?([\-a-zA-Z0-9._]*)",
        r"\b(8|9|26)\.(0|4|7|10)(?:\.([0-9]{1,3}))?((?:-(?:ndb|cluster|commercial|debug|log|dmr|rc)[0-9a-zA-Z.\-_]*)?)\b",
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) is not None else 0
            suffix = match.group(4) or ""
            raw_ver = f"{major}.{minor}.{patch}{suffix}" if match.group(3) is not None else f"{major}.{minor}{suffix}"
            is_cluster = ("ndb" in suffix.lower()) or ("cluster" in suffix.lower()) or ("mysql cluster" in text.lower())
            return major, minor, patch, is_cluster, raw_ver

    return None


def is_mysql_version_vulnerable(
    major: int,
    minor: int,
    patch: int,
    is_cluster: bool = False,
    raw_str: str = "",
) -> Tuple[bool, str]:
    """
    Evaluates whether an Oracle MySQL Server or MySQL Cluster version is affected
    by CVE-2026-114952 (CVSS 9.1 Critical):
      - MySQL Server / Cluster 8.4.0 - 8.4.13
      - MySQL Server / Cluster 9.7.0 - 9.7.4
      - MySQL Server / Cluster 26.10 (26.10.0)
      - MySQL Cluster (NDB) 8.0.0 - 8.0.50
    """
    product_label = "Oracle MySQL Cluster" if is_cluster else "Oracle MySQL Server"
    ver_display = raw_str or f"{major}.{minor}.{patch}"

    if is_cluster and major == 8 and minor == 0:
        if 0 <= patch <= 50:
            return True, (
                f"{product_label} {ver_display} falls within affected branch 8.0.0-8.0.50 "
                f"for CVE-2026-114952 (CVSS 9.1 Critical; fixed in >= 8.0.51)."
            )
        return False, f"{product_label} {ver_display} is patched (>= 8.0.51) against CVE-2026-114952."

    if major == 8 and minor == 4:
        if 0 <= patch <= 13:
            return True, (
                f"{product_label} {ver_display} falls within affected branch 8.4.0-8.4.13 "
                f"for CVE-2026-114952 (CVSS 9.1 Critical; fixed in >= 8.4.14)."
            )
        return False, f"{product_label} {ver_display} is patched (>= 8.4.14) against CVE-2026-114952."

    if major == 9 and minor == 7:
        if 0 <= patch <= 4:
            return True, (
                f"{product_label} {ver_display} falls within affected branch 9.7.0-9.7.4 "
                f"for CVE-2026-114952 (CVSS 9.1 Critical; fixed in >= 9.7.5)."
            )
        return False, f"{product_label} {ver_display} is patched (>= 9.7.5) against CVE-2026-114952."

    if major == 26 and minor == 10:
        if patch == 0:
            return True, (
                f"{product_label} {ver_display} is affected by CVE-2026-114952 "
                f"(CVSS 9.1 Critical, affected version 26.10; apply November 2026 Oracle CPU)."
            )
        return False, f"{product_label} {ver_display} is patched (> 26.10.0) against CVE-2026-114952."

    return False, f"{product_label} {ver_display} is outside the affected branches for CVE-2026-114952."


class MySQLAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: Oracle MySQL Server & MySQL Cluster Version Compliance Audit
    (CVE-2026-114952 - CVSS 9.1 Critical).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Oracle MySQL Server & Cluster Version Compliance Audit (CVE-2026-114952)",
            "description": (
                "Passive version compliance check for Oracle MySQL Server (8.4.0-8.4.13, 9.7.0-9.7.4, 26.10) "
                "and MySQL Cluster (8.0.0-8.0.50, 8.4.0-8.4.13, 9.7.0-9.7.4, 26.10) against CVE-2026-114952 (CVSS 9.1)."
            ),
            "severity": "CRITICAL",
            "cve": "CVE-2026-114952",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_MYSQL_PORTS.copy()
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

                if port in self.target_ports or "mysql" in s_name or "ndb" in s_name:
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

    def read_mysql_handshake_banner(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[str]:
        """
        Passively reads the initial server greeting packet sent by MySQL on TCP connect
        without transmitting any commands or authentication data.
        """
        sock = None
        try:
            sock = socket.create_connection((target_ip, port), timeout=timeout)
            raw = sock.recv(512)
            if not raw or len(raw) < 6:
                return None

            proto = raw[4]
            if proto == 0x0A:
                # Standard MySQL Protocol v10 Handshake: null-terminated version string starts at byte 5
                end_idx = raw.find(b"\x00", 5)
                if end_idx != -1:
                    return raw[5:end_idx].decode("utf-8", errors="replace").strip()

            # Fallback: decode printable text from greeting / error packet
            decoded = raw[4:].decode("utf-8", errors="replace")
            return decoded.strip()
        except (socket.timeout, ConnectionRefusedError):
            return None
        except Exception as e:
            logger.debug(f"MySQL greeting read failed on {target_ip}:{port}: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def probe_http_banner(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[str]:
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

            conn.request(
                "GET",
                "/",
                headers={
                    "User-Agent": "RTMS-Security-Audit/1.0 (Plugin CVE-2026-114952)",
                    "Accept": "application/json,text/plain,*/*",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()
            body = resp.read(4096).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return f"{headers}\n{body}"
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        if port in TCP_GREETING_PORTS or port not in (80, 443, 8080, 8443):
            banner = self.read_mysql_handshake_banner(target_ip, port, timeout=timeout)
            if banner:
                ver_info = parse_mysql_version(banner)
                if ver_info:
                    major, minor, patch, is_cluster, ver_str = ver_info
                    is_vuln, reason = is_mysql_version_vulnerable(major, minor, patch, is_cluster, ver_str)
                    return {
                        "port": port,
                        "service_detected": True,
                        "version": ver_str,
                        "source": "MySQL Initial Handshake Greeting",
                        "is_vulnerable": is_vuln,
                        "reason": reason,
                    }

        http_text = self.probe_http_banner(target_ip, port, timeout=timeout)
        if http_text and "mysql" in http_text.lower():
            ver_info = parse_mysql_version(http_text)
            if ver_info:
                major, minor, patch, is_cluster, ver_str = ver_info
                is_vuln, reason = is_mysql_version_vulnerable(major, minor, patch, is_cluster, ver_str)
                return {
                    "port": port,
                    "service_detected": True,
                    "version": ver_str,
                    "source": "MySQL HTTP/REST Endpoint Banner",
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
                    f"- [{port_label}] MySQL {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )
            else:
                safe_findings.append(
                    f"- [{port_label}] MySQL {result.get('version')} detected via "
                    f"{result.get('source')}. Result: {result.get('reason')}"
                )

        if vulnerable_findings:
            proof = (
                f"CVE-2026-114952 affected Oracle MySQL version detected on {target_ip}.\n"
                + "\n".join(vulnerable_findings)
            )
            details = (
                f"CRITICAL COMPLIANCE FINDING (CVE-2026-114952 - CVSS 9.1):\n"
                f"The target host {target_ip} runs an affected Oracle MySQL Server or MySQL Cluster release.\n\n"
                f"Advisory Summary:\n"
                f"- CVE-2026-114952 (CVSS 9.1 Critical): Vulnerability in Oracle MySQL Server "
                f"(8.4.0-8.4.13, 9.7.0-9.7.4, 26.10) and MySQL Cluster (8.0.0-8.0.50, 8.4.0-8.4.13, "
                f"9.7.0-9.7.4, 26.10) allowing unauthenticated network compromise of critical data.\n\n"
                f"Affected Endpoints:\n" + "\n".join(vulnerable_findings) + "\n\n"
                f"Remediation:\n"
                f"1. Apply the Oracle Critical Patch Update (upgrade MySQL 8.4 to >= 8.4.14, 9.7 to >= 9.7.5, "
                f"MySQL Cluster 8.0 to >= 8.0.51).\n"
                f"2. Restrict MySQL port exposure (3306/33060) to trusted internal application subnets."
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        if safe_findings:
            proof = f"Audited ports: {ports_to_scan}\n" + "\n".join(safe_findings)
            details = (
                f"Safe: Oracle MySQL instance on {target_ip} is not affected by CVE-2026-114952:\n"
                + "\n".join(safe_findings)
            )
            return self.format_result("OK", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {ports_to_scan}",
            details="No affected Oracle MySQL Server or MySQL Cluster services detected on target ports.",
        )


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Passive version compliance check for Oracle MySQL Server & Cluster (CVE-2026-114952)."
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        type=int,
        default=DEFAULT_MYSQL_PORTS,
        help="Ports to inspect (default: 3306 33060 3307 3308 8080 8443)",
    )
    parser.add_argument("--timeout", type=float, default=4.0, help="Connection timeout in seconds (default: 4.0)")

    args = parser.parse_args()

    plugin = MySQLAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No target ports selected among: {args.ports}")
        sys.exit(0)

    res = plugin.run_audit(args.target, args.ports)
    status = res.get("status", "Unknown")

    if status == "Vulnerable":
        print(f"[VULNERABLE] {args.target} runs an Oracle MySQL version affected by CVE-2026-114952.\n")
        print(res.get("details", ""))
        sys.exit(1)
    else:
        print(f"[OK] {args.target}: {res.get('details', '')}")
        sys.exit(0)
