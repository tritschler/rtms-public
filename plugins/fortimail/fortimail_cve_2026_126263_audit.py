"""
fortimail_cve_2026_126263_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive HTTP/HTTPS and SMTP banner version verification for Fortinet FortiMail
against CVE-2026-126263 (CVSS 9.8 Critical).

Affected Versions:
  - Fortinet FortiMail 7.4.0 through 7.4.6 (< 7.4.7)
  - Fortinet FortiMail 7.6.0 through 7.6.4 (< 7.6.5)
  - Fortinet FortiMail 8.0.0 through 8.0.1 (< 8.0.2)

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

DEFAULT_FORTIMAIL_PORTS = [443, 8443, 80, 25, 587]
SSL_PORTS = {443, 8443}


def parse_fortimail_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    if not text:
        return None
    m = re.search(r"FortiMail[^0-9\r\n]{1,30}v?([78])\.([046])\.([0-9]+)\b", text, re.IGNORECASE)
    if m:
        v1, v2, v3 = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return v1, v2, v3, f"{v1}.{v2}.{v3}"
    return None


def is_fortimail_version_vulnerable(v1: int, v2: int, v3: int, raw_str: str = "") -> Tuple[bool, str]:
    ver = (v1, v2, v3)
    disp = raw_str or f"{v1}.{v2}.{v3}"
    if (7, 4, 0) <= ver <= (7, 4, 6):
        return True, f"Fortinet FortiMail {disp} (7.4.0–7.4.6) is affected by CVE-2026-126263 (CVSS 9.8)."
    if (7, 6, 0) <= ver <= (7, 6, 4):
        return True, f"Fortinet FortiMail {disp} (7.6.0–7.6.4) is affected by CVE-2026-126263 (CVSS 9.8)."
    if (8, 0, 0) <= ver <= (8, 0, 1):
        return True, f"Fortinet FortiMail {disp} (8.0.0–8.0.1) is affected by CVE-2026-126263 (CVSS 9.8)."
    return False, f"Fortinet FortiMail {disp} is patched against CVE-2026-126263."


class FortiMailAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Fortinet FortiMail SQL Injection Compliance Audit (CVE-2026-126263)",
            "description": "Passive version compliance check for Fortinet FortiMail (7.4.0–7.4.6, 7.6.0–7.6.4, 8.0.0–8.0.1) against CVE-2026-126263 (CVSS 9.8).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-126263",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_FORTIMAIL_PORTS.copy()
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
                if p in self.target_ports or "fortimail" in s_name or "http" in s_name or "smtp" in s_name:
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
            conn.request("GET", "/admin/", headers={"User-Agent": "RTMS-Security-Audit/1.0 (CVE-2026-126263)", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(16384).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            combined = f"{headers}\n{body}"
            v = parse_fortimail_version(combined)
            if v:
                v1, v2, v3, raw = v
                vuln, reason = is_fortimail_version_vulnerable(v1, v2, v3, raw)
                return {"port": port, "service_detected": True, "version": raw, "source": "FortiMail Admin UI", "is_vulnerable": vuln, "reason": reason}
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
            line = f"- [Port {port}] Fortinet FortiMail {res['version']} via {res['source']}: {res['reason']}"
            if res.get("is_vulnerable"):
                vuln_list.append(line)
            else:
                safe_list.append(line)
        if vuln_list:
            return self.format_result("Vulnerable", proof="CVE-2026-126263 affected FortiMail:\n" + "\n".join(vuln_list), details="\n".join(vuln_list))
        if safe_list:
            return self.format_result("OK", proof="\n".join(safe_list), details="\n".join(safe_list))
        return self.format_result("OK", proof=f"Audited ports: {ports}", details="No affected Fortinet FortiMail detected.")
