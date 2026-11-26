"""
hpe_arubaos_cve_2026_95787_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS management banner version verification
for HPE ArubaOS (AOS-10) against CVE-2026-95787 (CVSS 10.0 Critical).

Affected Versions:
  - HPE ArubaOS 10.4.0.0 through 10.4.1.13 (< 10.4.1.14)
  - HPE ArubaOS 10.7.0.0 through 10.7.2.6 (< 10.7.2.7)
  - HPE ArubaOS 10.8.0.0 through 10.8.1.1 (< 10.8.1.2)

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
                return self.format_result("Skipped", details="Requirements not met.")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

logger = logging.getLogger(__name__)

DEFAULT_ARUBAOS_PORTS = [4343, 443, 8443, 80, 8080]
SSL_PORTS = {4343, 443, 8443}


def parse_hpe_arubaos_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    if not text:
        return None
    patterns = [
        r"(?:ArubaOS|AOS(?:-10)?|HPE\s+Aruba\s+Networking)[^0-9\r\n]{1,35}\b(10)\.([0-9]+)\.([0-9]+)\.([0-9]+)\b",
        r'arubaos[_-]?version[\s:="\']+v?(10)\.([0-9]+)\.([0-9]+)\.([0-9]+)\b',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            v1, v2, v3, v4 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
            raw = f"{v1}.{v2}.{v3}.{v4}"
            return v1, v2, v3, v4, raw
    return None


def is_hpe_arubaos_version_vulnerable(v1: int, v2: int, v3: int, v4: int, raw_str: str = "") -> Tuple[bool, str]:
    ver = (v1, v2, v3, v4)
    disp = raw_str or f"{v1}.{v2}.{v3}.{v4}"
    if (10, 4, 0, 0) <= ver <= (10, 4, 1, 13):
        return True, f"HPE ArubaOS {disp} (10.4.0.0–10.4.1.13) is affected by CVE-2026-95787 (CVSS 10.0)."
    if (10, 7, 0, 0) <= ver <= (10, 7, 2, 6):
        return True, f"HPE ArubaOS {disp} (10.7.0.0–10.7.2.6) is affected by CVE-2026-95787 (CVSS 10.0)."
    if (10, 8, 0, 0) <= ver <= (10, 8, 1, 1):
        return True, f"HPE ArubaOS {disp} (10.8.0.0–10.8.1.1) is affected by CVE-2026-95787 (CVSS 10.0)."
    return False, f"HPE ArubaOS {disp} is patched against CVE-2026-95787."


class HPEArubaOSAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "HPE ArubaOS (AOS-10) PAPI Auth Bypass Audit (CVE-2026-95787)",
            "description": "Passive version compliance check for HPE ArubaOS (10.4 <= 10.4.1.13, 10.7 <= 10.7.2.6, 10.8 <= 10.8.1.1) against CVE-2026-95787 (CVSS 10.0).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-95787",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_ARUBAOS_PORTS.copy()
        self.discovered_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        self.discovered_ports = []
        if isinstance(target_services, dict):
            for p_raw, s_info in target_services.items():
                try:
                    p = int(p_raw)
                except (ValueError, TypeError):
                    continue
                s_name = str(s_info).lower()
                if p in self.target_ports or "aruba" in s_name or "http" in s_name:
                    self.discovered_ports.append(p)
        elif isinstance(target_services, (list, set, tuple)):
            for p_raw in target_services:
                try:
                    p = int(p_raw)
                    if p in self.target_ports:
                        self.discovered_ports.append(p)
                except (ValueError, TypeError):
                    continue
        self.discovered_ports = sorted(list(set(self.discovered_ports)))
        return len(self.discovered_ports) > 0

    def probe_http_endpoint(self, target_ip: str, port: int, path: str = "/", timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        conn = None
        try:
            if port in SSL_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target_ip, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target_ip, port=port, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": "RTMS-Security-Audit/1.0 (CVE-2026-95787)", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(16384).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return {"port": port, "status_code": resp.status, "headers": headers, "body_snippet": body[:8192]}
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        for path, label in [("/screens/wms/wms.login", "ArubaOS WebUI"), ("/", "HTTP Root")]:
            pr = self.probe_http_endpoint(target_ip, port, path, timeout)
            if not pr:
                continue
            combined = f"{pr.get('headers', {})}\n{pr.get('body_snippet', '')}"
            if "aruba" in combined.lower() or "aos" in combined.lower():
                v = parse_hpe_arubaos_version(combined)
                if v:
                    v1, v2, v3, v4, raw = v
                    vuln, reason = is_hpe_arubaos_version_vulnerable(v1, v2, v3, v4, raw)
                    return {"port": port, "service_detected": True, "version": raw, "source": label, "is_vulnerable": vuln, "reason": reason}
        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        ports = self.discovered_ports if self.discovered_ports else self.target_ports
        vuln_list: List[str] = []
        safe_list: List[str] = []
        for port in ports:
            res = self.inspect_target_port(target_ip, port)
            if not res or not res.get("service_detected"):
                continue
            line = f"- [Port {port}] HPE ArubaOS {res['version']} via {res['source']}: {res['reason']}"
            if res.get("is_vulnerable"):
                vuln_list.append(line)
            else:
                safe_list.append(line)
        if vuln_list:
            return self.format_result("Vulnerable", proof="CVE-2026-95787 affected HPE ArubaOS:\n" + "\n".join(vuln_list), details="\n".join(vuln_list))
        if safe_list:
            return self.format_result("OK", proof="\n".join(safe_list), details="\n".join(safe_list))
        return self.format_result("OK", proof=f"Audited ports: {ports}", details="No affected HPE ArubaOS detected.")
