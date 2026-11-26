"""
oracle_access_manager_cve_2026_91510_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive, read-only HTTP/HTTPS banner and SSO metadata version verification
for Oracle Access Manager (OAM) against CVE-2026-91510 (CVSS 10.0 Critical).

Affected Versions:
  - Oracle Access Manager 12.2.1.4.0 (< 12.2.1.4.1 / unpatched CPU)
  - Oracle Access Manager 14.1.2.1.0 (< 14.1.2.1.1 / unpatched CPU)

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

DEFAULT_OAM_PORTS = [14100, 14101, 7001, 7002, 443, 80, 8443, 8080]
SSL_PORTS = {443, 8443, 7002, 14101}


def parse_oam_version(text: str) -> Optional[Tuple[int, int, int, int, int, str]]:
    if not text:
        return None
    patterns = [
        r"(?:Oracle\s+Access\s+Manager|OAM(?:\s+Server)?)[^0-9\r\n]{1,35}\b(1[24])\.([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b",
        r'oam[_-]?version[\s:="\']+v?(1[24])\.([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            v1, v2, v3, v4 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
            v5 = int(m.group(5)) if m.group(5) is not None else 0
            raw = f"{v1}.{v2}.{v3}.{v4}.{v5}"
            return v1, v2, v3, v4, v5, raw
    return None


def is_oam_version_vulnerable(v1: int, v2: int, v3: int, v4: int, v5: int = 0, raw_str: str = "") -> Tuple[bool, str]:
    ver = (v1, v2, v3, v4, v5)
    disp = raw_str or f"{v1}.{v2}.{v3}.{v4}.{v5}"
    if (12, 2, 1, 0, 0) <= ver <= (12, 2, 1, 4, 0):
        return True, f"Oracle Access Manager {disp} (<= 12.2.1.4.0) is affected by CVE-2026-91510 (CVSS 10.0)."
    if (14, 1, 2, 0, 0) <= ver <= (14, 1, 2, 1, 0):
        return True, f"Oracle Access Manager {disp} (<= 14.1.2.1.0) is affected by CVE-2026-91510 (CVSS 10.0)."
    return False, f"Oracle Access Manager {disp} is patched against CVE-2026-91510."


class OracleAccessManagerAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Oracle Access Manager Authentication Engine Audit (CVE-2026-91510)",
            "description": "Passive version compliance check for Oracle Access Manager (12.2.1.4.0 & 14.1.2.1.0) against CVE-2026-91510 (CVSS 10.0).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-91510",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_OAM_PORTS.copy()
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
                if p in self.target_ports or "oracle" in s_name or "oam" in s_name or "http" in s_name:
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

    def probe_http_endpoint(self, target_ip: str, port: int, path: str = "/oamconsole", timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        conn = None
        try:
            if port in SSL_PORTS:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target_ip, port=port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(target_ip, port=port, timeout=timeout)
            conn.request("GET", path, headers={"User-Agent": "RTMS-Security-Audit/1.0 (CVE-2026-91510)", "Connection": "close"})
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
        for path, label in [("/oamconsole", "OAM Console"), ("/oam/server/obrareq.cgi", "OAM Auth Engine"), ("/", "HTTP Root")]:
            pr = self.probe_http_endpoint(target_ip, port, path, timeout)
            if not pr:
                continue
            combined = f"{pr.get('headers', {})}\n{pr.get('body_snippet', '')}"
            if "oracle access manager" in combined.lower() or "oam" in combined.lower():
                v = parse_oam_version(combined)
                if v:
                    v1, v2, v3, v4, v5, raw = v
                    vuln, reason = is_oam_version_vulnerable(v1, v2, v3, v4, v5, raw)
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
            line = f"- [Port {port}] Oracle Access Manager {res['version']} via {res['source']}: {res['reason']}"
            if res.get("is_vulnerable"):
                vuln_list.append(line)
            else:
                safe_list.append(line)
        if vuln_list:
            return self.format_result("Vulnerable", proof="CVE-2026-91510 affected OAM:\n" + "\n".join(vuln_list), details="\n".join(vuln_list))
        if safe_list:
            return self.format_result("OK", proof="\n".join(safe_list), details="\n".join(safe_list))
        return self.format_result("OK", proof=f"Audited ports: {ports}", details="No affected Oracle Access Manager detected.")
