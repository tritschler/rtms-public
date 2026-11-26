"""
adobe_campaign_cve_2026_125675_audit.py

Standalone Defensive Version Compliance Tool & External Plugin for RTMS Suite.
Performs passive HTTP/HTTPS version verification for Adobe Campaign Classic (ACC)
against the November 2026 Critical Advisories (11 CVEs: CVE-2026-125675, CVE-2026-123987,
CVE-2026-123721, CVE-2026-123723, CVE-2026-125718, CVE-2026-123342, CVE-2026-125717,
CVE-2026-123722, CVE-2026-125676, CVE-2026-123986, CVE-2026-125716 — CVSS up to 9.9).

Affected Versions:
  - Adobe Campaign Classic <= 7.4.4 build 9403 (< 7.4.4 build 9404)
  - Adobe Campaign Classic 7.4.5 <= build 9420 (< 7.4.5 build 9421)

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

DEFAULT_ACC_PORTS = [8080, 443, 80, 8443]
SSL_PORTS = {443, 8443}


def parse_adobe_campaign_version(text: str) -> Optional[Tuple[int, int, int, int, str]]:
    if not text:
        return None
    m = re.search(
        r"Adobe\s+Campaign(?:\s+Classic)?[^0-9\r\n]{1,35}\b(7)\.(4)\.([0-9]+)(?:\s+build\s+([0-9]+))?\b",
        text,
        re.IGNORECASE,
    )
    if m:
        v1, v2, v3 = int(m.group(1)), int(m.group(2)), int(m.group(3))
        build = int(m.group(4)) if m.group(4) is not None else 0
        raw = f"{v1}.{v2}.{v3} build {build}" if build else f"{v1}.{v2}.{v3}"
        return v1, v2, v3, build, raw
    return None


def is_adobe_campaign_version_vulnerable(v1: int, v2: int, v3: int, build: int = 0, raw_str: str = "") -> Tuple[bool, str]:
    ver = (v1, v2, v3)
    disp = raw_str or f"{v1}.{v2}.{v3}"
    if ver < (7, 4, 4) or (ver == (7, 4, 4) and (build == 0 or build <= 9403)):
        return True, (
            f"Adobe Campaign Classic {disp} (<= 7.4.4 build 9403) is affected by CVE-2026-125675, "
            f"CVE-2026-123987, CVE-2026-123721, CVE-2026-123723, CVE-2026-125718, CVE-2026-123342, "
            f"CVE-2026-125717, CVE-2026-123722, CVE-2026-125676, CVE-2026-123986, and CVE-2026-125716 (CVSS 9.9)."
        )
    if ver == (7, 4, 5) and (build == 0 or build <= 9420):
        return True, (
            f"Adobe Campaign Classic {disp} (7.4.5 <= build 9420) is affected by CVE-2026-125675 and related advisories (CVSS 9.9)."
        )
    return False, f"Adobe Campaign Classic {disp} is patched against CVE-2026-125675."


class AdobeCampaignAuditPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.info = {
            "name": "Adobe Campaign Classic Multi-CVE Code Injection Audit (CVE-2026-125675 / CVE-2026-123987)",
            "description": "Passive version compliance check for Adobe Campaign Classic (<= 7.4.4 build 9403, 7.4.5 <= build 9420) against 11 critical CVEs (CVE-2026-125675 — CVSS 9.9).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-125675",
            "version": "1.0.0",
        }
        self.target_ports = DEFAULT_ACC_PORTS.copy()
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
                if p in self.target_ports or "adobe" in s_name or "campaign" in s_name or "http" in s_name:
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
            conn.request("GET", "/nl/jsp/logon.jsp", headers={"User-Agent": "RTMS-Security-Audit/1.0 (CVE-2026-125675)", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(16384).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}
            combined = f"{headers}\n{body}"
            v = parse_adobe_campaign_version(combined)
            if v:
                v1, v2, v3, bld, raw = v
                vuln, reason = is_adobe_campaign_version_vulnerable(v1, v2, v3, bld, raw)
                return {"port": port, "service_detected": True, "version": raw, "source": "Adobe Campaign Logon", "is_vulnerable": vuln, "reason": reason}
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
            line = f"- [Port {port}] Adobe Campaign Classic {res['version']} via {res['source']}: {res['reason']}"
            if res.get("is_vulnerable"):
                vuln_list.append(line)
            else:
                safe_list.append(line)
        if vuln_list:
            return self.format_result("Vulnerable", proof="CVE-2026-125675 affected Adobe Campaign Classic:\n" + "\n".join(vuln_list), details="\n".join(vuln_list))
        if safe_list:
            return self.format_result("OK", proof="\n".join(safe_list), details="\n".join(safe_list))
        return self.format_result("OK", proof=f"Audited ports: {ports}", details="No affected Adobe Campaign Classic detected.")
