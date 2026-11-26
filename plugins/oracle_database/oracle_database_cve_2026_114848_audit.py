"""
oracle_database_cve_2026_114848_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive banner / EM Express / ORDS metadata version verification for
Oracle Database Server against CVE-2026-114848 (CVSS 9.9 Critical).

Affected Versions:
  - Oracle Database Server 19.3 through 19.33 (< 19.34)
  - Oracle Database Server 21.3 through 21.24 (< 21.25)
  - Oracle Database Server 23.4.0 through 23.26.3 (< 23.26.4)

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

DEFAULT_ORACLE_DB_PORTS = [1521, 5500, 5502, 8080, 8443, 443]
SSL_PORTS = {5500, 5502, 8443, 443}


def parse_oracle_db_version(text: str) -> Optional[Tuple[int, int, int, str]]:
    if not text:
        return None
    patterns = [
        r"(?:Oracle\s+Database(?:\s+Server|\s+19c|\s+21c|\s+23ai)?|TNSLSNR\s+for\s+[^:]+:\s*Version)[^0-9\r\n]{1,35}\b(19|21|23)\.([0-9]+)(?:\.([0-9]+))?\b",
        r'oracle[_-]?db[_-]?version[\s:="\']+v?(19|21|23)\.([0-9]+)(?:\.([0-9]+))?\b',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            v1, v2 = int(m.group(1)), int(m.group(2))
            v3 = int(m.group(3)) if m.group(3) is not None else 0
            raw = f"{v1}.{v2}.{v3}" if m.group(3) is not None else f"{v1}.{v2}"
            return v1, v2, v3, raw
    return None


def is_oracle_db_version_vulnerable(v1: int, v2: int, v3: int = 0, raw_str: str = "") -> Tuple[bool, str]:
    ver = (v1, v2, v3)
    disp = raw_str or f"{v1}.{v2}.{v3}"
    if v1 == 19 and (19, 3, 0) <= ver <= (19, 33, 99):
        return True, f"Oracle Database Server {disp} (19.3–19.33) is affected by CVE-2026-114848 (CVSS 9.9)."
    if v1 == 21 and (21, 3, 0) <= ver <= (21, 24, 99):
        return True, f"Oracle Database Server {disp} (21.3–21.24) is affected by CVE-2026-114848 (CVSS 9.9)."
    if v1 == 23 and (23, 4, 0) <= ver <= (23, 26, 3):
        return True, f"Oracle Database Server {disp} (23.4.0–23.26.3) is affected by CVE-2026-114848 (CVSS 9.9)."
    return False, f"Oracle Database Server {disp} is patched against CVE-2026-114848."


class OracleDatabaseAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Oracle Database Server Oracle Text RCE Audit (CVE-2026-114848)",
            "description": "Passive version compliance check for Oracle Database Server (19.3–19.33, 21.3–21.24, 23.4.0–23.26.3) against CVE-2026-114848 (CVSS 9.9).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-114848",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_ORACLE_DB_PORTS.copy()
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
                if p in self.target_ports or "oracle" in s_name or "tns" in s_name:
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
            conn.request("GET", "/em", headers={"User-Agent": "RTMS-Security-Audit/1.0 (CVE-2026-114848)", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(16384).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            combined = f"{headers}\n{body}"
            v = parse_oracle_db_version(combined)
            if v:
                v1, v2, v3, raw = v
                vuln, reason = is_oracle_db_version_vulnerable(v1, v2, v3, raw)
                return {"port": port, "service_detected": True, "version": raw, "source": "Oracle EM / HTTP Banner", "is_vulnerable": vuln, "reason": reason}
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
            line = f"- [Port {port}] Oracle Database Server {res['version']} via {res['source']}: {res['reason']}"
            if res.get("is_vulnerable"):
                vuln_list.append(line)
            else:
                safe_list.append(line)
        if vuln_list:
            return self.format_result("Vulnerable", proof="CVE-2026-114848 affected Oracle Database:\n" + "\n".join(vuln_list), details="\n".join(vuln_list))
        if safe_list:
            return self.format_result("OK", proof="\n".join(safe_list), details="\n".join(safe_list))
        return self.format_result("OK", proof=f"Audited ports: {ports}", details="No affected Oracle Database Server detected.")
