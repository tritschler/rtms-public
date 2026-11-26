"""
typo3_cms_cve_2026_119623_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive HTTP/HTTPS version verification for TYPO3 CMS against
CVE-2026-119623 (CVSS 9.4 Critical).

Affected Versions:
  - TYPO3 CMS 10.0.0 before 10.4.63
  - TYPO3 CMS 11.0.0 before 11.5.57
  - TYPO3 CMS 12.0.0 before 12.4.52
  - TYPO3 CMS 13.0.0 before 13.4.40
  - TYPO3 CMS 14.0.0 before 14.3.12

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

DEFAULT_TYPO3_PORTS = [80, 443, 8080, 8443]
SSL_PORTS = {443, 8443}


def parse_typo3_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    if not text:
        return None
    m = re.search(r"TYPO3(?:\s+CMS)?[^0-9\r\n]{1,30}v?(1[0-4])\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
    if m:
        v1, v2, v3 = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return v1, v2, v3, f"{v1}.{v2}.{v3}"
    return None


def is_typo3_version_vulnerable(v1: int, v2: int, v3: int, raw_str: str = "") -> Tuple[bool, str]:
    ver = (v1, v2, v3)
    disp = raw_str or f"{v1}.{v2}.{v3}"
    bounds = {
        10: (10, 4, 63),
        11: (11, 5, 57),
        12: (12, 4, 52),
        13: (13, 4, 40),
        14: (14, 3, 12),
    }
    if v1 in bounds and ver < bounds[v1]:
        b = bounds[v1]
        return True, f"TYPO3 CMS {disp} (< {b[0]}.{b[1]}.{b[2]}) is affected by CVE-2026-119623 (CVSS 9.4)."
    return False, f"TYPO3 CMS {disp} is patched against CVE-2026-119623."


class Typo3CmsAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "TYPO3 CMS First-Install Re-Enablement Compliance Audit (CVE-2026-119623)",
            "description": "Passive version compliance check for TYPO3 CMS (< 10.4.63, < 11.5.57, < 12.4.52, < 13.4.40, < 14.3.12) against CVE-2026-119623 (CVSS 9.4).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-119623",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_TYPO3_PORTS.copy()
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
                if p in self.target_ports or "typo3" in s_name or "http" in s_name:
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

    def inspect_target_port(self, target_ip: str, port: int, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        conn = None
        try:
            if port in SSL_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target_ip, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target_ip, port=port, timeout=timeout)
            conn.request("GET", "/typo3/sysext/core/Documentation/Changelog", headers={"User-Agent": "RTMS-Security-Audit/1.0 (CVE-2026-119623)", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(16384).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            combined = f"{headers}\n{body}"
            v = parse_typo3_version(combined)
            if v:
                v1, v2, v3, raw = v
                vuln, reason = is_typo3_version_vulnerable(v1, v2, v3, raw)
                return {"port": port, "service_detected": True, "version": raw, "source": "TYPO3 Metadata", "is_vulnerable": vuln, "reason": reason}
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        ports = self.discovered_ports if self.discovered_ports else self.target_ports
        vuln_list: List[str] = []
        safe_list: List[str] = []
        for port in ports:
            res = self.inspect_target_port(target_ip, port)
            if not res or not res.get("service_detected"):
                continue
            line = f"- [Port {port}] TYPO3 CMS {res['version']} via {res['source']}: {res['reason']}"
            if res.get("is_vulnerable"):
                vuln_list.append(line)
            else:
                safe_list.append(line)
        if vuln_list:
            return self.format_result("Vulnerable", proof="CVE-2026-119623 affected TYPO3 CMS:\n" + "\n".join(vuln_list), details="\n".join(vuln_list))
        if safe_list:
            return self.format_result("OK", proof="\n".join(safe_list), details="\n".join(safe_list))
        return self.format_result("OK", proof=f"Audited ports: {ports}", details="No affected TYPO3 CMS detected.")
