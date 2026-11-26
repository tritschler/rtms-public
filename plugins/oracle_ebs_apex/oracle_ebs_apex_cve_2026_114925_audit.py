"""
oracle_ebs_apex_cve_2026_114925_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive HTTP/HTTPS version verification for Oracle E-Business Suite (EBS)
and Oracle APEX against the November 2026 Critical Advisories (6 CVEs):
  - CVE-2026-114925 (CVSS 9.8): Oracle EBS Applications Framework REST Services
  - CVE-2026-114924 (CVSS 9.8): Oracle EBS Application Object Library Core
  - CVE-2026-114863 (CVSS 9.8): Oracle EBS Universal Work Queue
  - CVE-2026-114881 (CVSS 9.1): Oracle EBS Document Management & Collaboration
  - CVE-2026-101691 (CVSS 9.3): Oracle EBS Mobile Field Service
  - CVE-2026-114850 (CVSS 9.8): Oracle APEX (24.1.22, 24.2.21, 26.1.5, 26.2.0)

Affected Versions:
  - Oracle E-Business Suite 12.2.3 through 12.2.15 (< 12.2.16)
  - Oracle APEX <= 24.1.22, 24.2.x <= 24.2.21, 26.1.x <= 26.1.5, 26.2.0

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

DEFAULT_EBS_PORTS = [8000, 4443, 443, 80, 8080, 8443]
SSL_PORTS = {443, 4443, 8443}


def parse_oracle_ebs_apex_version(text: str) -> Optional[Tuple[str, int, int, int, str]]:
    if not text:
        return None
    ebs_m = re.search(r"Oracle\s+E-Business\s+Suite[^0-9\r\n]{1,30}\b(12)\.(2)\.([0-9]+)\b", text, re.IGNORECASE)
    if ebs_m:
        v1, v2, v3 = int(ebs_m.group(1)), int(ebs_m.group(2)), int(ebs_m.group(3))
        return "EBS", v1, v2, v3, f"12.2.{v3}"
    apex_m = re.search(r"Oracle\s+APEX[^0-9\r\n]{1,30}\b(2[46])\.([12])\.([0-9]+)\b", text, re.IGNORECASE)
    if apex_m:
        v1, v2, v3 = int(apex_m.group(1)), int(apex_m.group(2)), int(apex_m.group(3))
        return "APEX", v1, v2, v3, f"{v1}.{v2}.{v3}"
    return None


def is_oracle_ebs_apex_vulnerable(product: str, v1: int, v2: int, v3: int, raw_str: str = "") -> Tuple[bool, str]:
    ver = (v1, v2, v3)
    disp = raw_str or f"{v1}.{v2}.{v3}"
    if product.upper() == "EBS":
        if (12, 2, 3) <= ver <= (12, 2, 15):
            return True, (
                f"Oracle E-Business Suite {disp} (12.2.3–12.2.15) is affected by CVE-2026-114925, "
                f"CVE-2026-114924, CVE-2026-114863, CVE-2026-114881, and CVE-2026-101691 (CVSS 9.8)."
            )
        return False, f"Oracle E-Business Suite {disp} is patched against CVE-2026-114925."
    if (24, 1, 0) <= ver <= (24, 1, 22) or (24, 2, 0) <= ver <= (24, 2, 21) or (26, 1, 0) <= ver <= (26, 1, 5) or ver == (26, 2, 0):
        return True, f"Oracle APEX {disp} is affected by CVE-2026-114850 (CVSS 9.8)."
    return False, f"Oracle APEX {disp} is patched against CVE-2026-114850."


class OracleEbsApexAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Oracle E-Business Suite & Oracle APEX Multi-CVE Audit (CVE-2026-114925 / CVE-2026-114850)",
            "description": "Passive version compliance check for Oracle E-Business Suite (12.2.3–12.2.15) and Oracle APEX against CVE-2026-114925 and CVE-2026-114850 (CVSS 9.8).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-114925",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_EBS_PORTS.copy()
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
                if p in self.target_ports or "oracle" in s_name or "ebs" in s_name or "apex" in s_name or "http" in s_name:
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
            conn.request("GET", "/OA_HTML/AppsLogin", headers={"User-Agent": "RTMS-Security-Audit/1.0 (CVE-2026-114925)", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(16384).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            combined = f"{headers}\n{body}"
            v = parse_oracle_ebs_apex_version(combined)
            if v:
                prod, v1, v2, v3, raw = v
                vuln, reason = is_oracle_ebs_apex_vulnerable(prod, v1, v2, v3, raw)
                return {"port": port, "service_detected": True, "version": raw, "source": f"Oracle {prod} Login", "is_vulnerable": vuln, "reason": reason}
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
            line = f"- [Port {port}] {res['source']} {res['version']}: {res['reason']}"
            if res.get("is_vulnerable"):
                vuln_list.append(line)
            else:
                safe_list.append(line)
        if vuln_list:
            return self.format_result("Vulnerable", proof="CVE-2026-114925 / CVE-2026-114850 affected Oracle EBS/APEX:\n" + "\n".join(vuln_list), details="\n".join(vuln_list))
        if safe_list:
            return self.format_result("OK", proof="\n".join(safe_list), details="\n".join(safe_list))
        return self.format_result("OK", proof=f"Audited ports: {ports}", details="No affected Oracle E-Business Suite or APEX detected.")
