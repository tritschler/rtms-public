"""
openjdk_cve_2026_114938_audit.py

Standalone Defensive Compliance Tool & External Plugin for RTMS Suite.
Audits OpenJDK, Oracle Java SE, and Oracle GraalVM instances for CVE-2026-114938 ("Java4Shell"):
  - CVE-2026-114938 (CVSS v3.1 8.1 High — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H):
    Heap buffer overflow (62-63 bytes out-of-bounds write) in the HotSpot C2 JIT compiler
    intrinsic for java.util.Base64 decoding on x86_64 processors supporting AVX-512 VBMI
    (avx512vbmi instruction set extension).

Dual Execution Modes:
  1. RTMS Scanner Mode (Network -> Generic RTMS Local Agent on TCP port 12000):
     Queries the generic read-only inspection API (POST /api/audit/inspect or GET /api/inventory)
     of rtms-local-agent without any CVE-specific logic inside the agent.
  2. Standalone Local CLI Mode (Direct execution on the server itself):
     When executed via CLI without a remote IP (or with --local), inspects the local server
     directly via read-only filesystem & process table inspection (/proc/cpuinfo, /proc/<pid>/cmdline,
     JVM <JAVA_HOME>/release files, and package metadata) without requiring rtms-local-agent.

Affected Versions:
  - OpenJDK / Oracle Java SE / GraalVM 17.x: 17.0.6 through 17.0.21.0.3
  - OpenJDK / Oracle Java SE / GraalVM 21.x: 21.0.0 through 21.0.13.0.3
  - OpenJDK / Oracle Java SE / GraalVM 25.x: 25.0.0 through 25.0.5.0.3
  - OpenJDK / Oracle Java SE / GraalVM 27.x: 27.0.0 through 27.0.1.0.3

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors / 3TS Consulting SRL
"""

import http.client
import json
import logging
import os
import re
import socket
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

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
                return self.format_result(
                    "Skipped",
                    details="Requirements not met (RTMS Local Agent port 12000 not open on target).",
                )
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as exc:
                return self.format_result("Error", details=str(exc))

logger = logging.getLogger(__name__)

DEFAULT_AGENT_PORT = 12000


def parse_openjdk_version(text: str) -> Optional[Tuple[Tuple[int, int, int, int, int], str]]:
    """
    Extracts a normalized 5-tuple (major, minor, security, patch1, patch2) and raw string
    from OpenJDK / Oracle Java version outputs, release files, or distro package versions.

    Examples:
      - 'openjdk version "21.0.10" 2026-01-20' -> ((21, 0, 10, 0, 0), '21.0.10')
      - 'JAVA_VERSION="17.0.21.0.3"'           -> ((17, 0, 21, 0, 3), '17.0.21.0.3')
      - '21.0.13+7-1~deb12u1'                  -> ((21, 0, 13, 0, 0), '21.0.13')
      - 'java version "25.0.5"'                -> ((25, 0, 5, 0, 0), '25.0.5')
    """
    if not text:
        return None

    patterns = [
        r'JAVA_VERSION\s*=\s*"([0-9]{1,2}(?:\.[0-9]{1,3}){0,4})',
        r'(?:openjdk|java)\s+version\s+"([0-9]{1,2}(?:\.[0-9]{1,3}){0,4})',
        r'(?:OpenJDK|Java\(TM\))\s+[^\n]*?(?:build\s+)?([0-9]{1,2}(?:\.[0-9]{1,3}){1,4})',
        r'\b([12][0-9](?:\.[0-9]{1,3}){2,4})(?:\+[0-9]+|-|~|\b)',
    ]

    for pat in patterns:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            raw_ver = match.group(1).strip()
            parts = [int(x) for x in raw_ver.split(".")]
            while len(parts) < 5:
                parts.append(0)
            norm_tuple = (parts[0], parts[1], parts[2], parts[3], parts[4])
            return norm_tuple, raw_ver

    return None


def is_openjdk_version_vulnerable(ver_tuple: Tuple[int, int, int, int, int], raw_ver: str = "") -> Tuple[bool, str]:
    """
    Evaluates whether a normalized 5-part Java version falls within the affected ranges
    for CVE-2026-114938:
      - 17.x: 17.0.6 <= v <= 17.0.21.0.3 (introduced in JDK 17.0.6 via JDK-8290065)
      - 21.x: 21.0.0 <= v <= 21.0.13.0.3
      - 25.x: 25.0.0 <= v <= 25.0.5.0.3
      - 27.x: 27.0.0 <= v <= 27.0.1.0.3
    """
    major = ver_tuple[0]
    label = raw_ver or ".".join(str(x) for x in ver_tuple[:3])

    if major == 17:
        if (17, 0, 6, 0, 0) <= ver_tuple <= (17, 0, 21, 0, 3):
            return True, f"Java 17 branch version {label} is in affected range [17.0.6 .. 17.0.21.0.3]"
        if ver_tuple < (17, 0, 6, 0, 0):
            return False, f"Java 17 branch version {label} predates AVX-512 VBMI Base64 intrinsic (< 17.0.6)"
        return False, f"Java 17 branch version {label} is patched (> 17.0.21.0.3)"

    if major == 21:
        if (21, 0, 0, 0, 0) <= ver_tuple <= (21, 0, 13, 0, 3):
            return True, f"Java 21 LTS branch version {label} is in affected range [21.0.0 .. 21.0.13.0.3]"
        return False, f"Java 21 LTS branch version {label} is patched (> 21.0.13.0.3)"

    if major == 25:
        if (25, 0, 0, 0, 0) <= ver_tuple <= (25, 0, 5, 0, 3):
            return True, f"Java 25 LTS branch version {label} is in affected range [25.0.0 .. 25.0.5.0.3]"
        return False, f"Java 25 LTS branch version {label} is patched (> 25.0.5.0.3)"

    if major == 27:
        if (27, 0, 0, 0, 0) <= ver_tuple <= (27, 0, 1, 0, 3):
            return True, f"Java 27 branch version {label} is in affected range [27.0.0 .. 27.0.1.0.3]"
        return False, f"Java 27 branch version {label} is patched (> 27.0.1.0.3)"

    return False, f"Java {major} branch ({label}) is outside CVE-2026-114938 affected branches (17, 21, 25, 27)"


def _has_avx_mitigation_flag(cmdline_args: List[str]) -> bool:
    """
    Returns True if the JVM command line includes a flag capping AVX usage at <= 2
    (e.g., -XX:UseAVX=2, -XX:UseAVX=1, -XX:UseAVX=0), which disables AVX-512 intrinsics.
    """
    for arg in cmdline_args or []:
        arg_str = str(arg).strip()
        if re.search(r"-XX:UseAVX=[012]\b", arg_str):
            return True
    return False


def _read_text_file_safe(path: str, max_bytes: int = 262144) -> str:
    """Read-only helper compliant with RTMS AST security validator."""
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(max_bytes)
    except Exception:
        pass
    return ""


def _read_jdk_release_version(java_exe_or_home: str) -> Optional[str]:
    """
    Given a path to a java binary (e.g., /usr/lib/jvm/java-21-openjdk-amd64/bin/java)
    or a JAVA_HOME directory, reads the standard <JAVA_HOME>/release file to extract JAVA_VERSION.
    """
    if not java_exe_or_home:
        return None
    try:
        real_p = os.path.realpath(java_exe_or_home)
    except Exception:
        real_p = java_exe_or_home

    candidate_dirs = [
        real_p,
        os.path.dirname(real_p),
        os.path.dirname(os.path.dirname(real_p)),
    ]
    for d in candidate_dirs:
        rel_file = os.path.join(d, "release")
        content = _read_text_file_safe(rel_file, 16384)
        if content and "JAVA_VERSION" in content:
            return content
    return None


def inspect_local_host_directly() -> Dict[str, Any]:
    """
    Inspects the local host directly (Standalone CLI mode on the server itself)
    using strictly read-only filesystem and process inspection (no subprocess/shutil).
    """
    cpu_model = "Unknown CPU"
    cpu_flags: List[str] = []

    # 1. Read /proc/cpuinfo for CPU model and avx512vbmi flag
    cpuinfo = _read_text_file_safe("/proc/cpuinfo", 524288)
    if cpuinfo:
        flags_set = set()
        for line in cpuinfo.splitlines():
            if ":" not in line:
                continue
            k, v = [part.strip() for part in line.split(":", 1)]
            k_low = k.lower()
            if k_low in ("model name", "hardware", "processor") and cpu_model == "Unknown CPU" and not v.isdigit():
                cpu_model = v
            elif k_low in ("flags", "features"):
                for fl in v.lower().split():
                    flags_set.add(fl)
        cpu_flags = sorted(flags_set)

    has_avx512vbmi = "avx512vbmi" in cpu_flags

    # 2. Discover running Java processes & JVM arguments
    java_processes: List[Dict[str, Any]] = []
    detected_versions: List[Tuple[str, str]] = []  # (source, version_text)

    if psutil is not None:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    pname = (proc.info.get("name") or "").lower()
                    cmdline = proc.info.get("cmdline") or []
                    exe_path = proc.info.get("exe") or ""
                    if "java" in pname or (exe_path and exe_path.endswith("/java")):
                        has_mitig = _has_avx_mitigation_flag(cmdline)
                        java_processes.append({
                            "pid": proc.info.get("pid"),
                            "process": proc.info.get("name") or "java",
                            "exe": exe_path,
                            "cmdline": cmdline[:25],
                            "has_arg": has_mitig,
                        })
                        rel_txt = _read_jdk_release_version(exe_path)
                        if rel_txt:
                            detected_versions.append((f"running process PID {proc.info.get('pid')} ({exe_path})", rel_txt))
                except Exception:
                    continue
        except Exception:
            pass
    elif os.path.isdir("/proc"):
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                cmdline_raw = _read_text_file_safe(f"/proc/{entry}/cmdline", 16384)
                if not cmdline_raw:
                    continue
                parts = [p for p in cmdline_raw.split("\x00") if p]
                if not parts:
                    continue
                bin_base = os.path.basename(parts[0]).lower()
                if bin_base == "java" or "java" in bin_base:
                    exe_target = parts[0]
                    try:
                        exe_target = os.readlink(f"/proc/{entry}/exe")
                    except Exception:
                        pass
                    has_mitig = _has_avx_mitigation_flag(parts)
                    java_processes.append({
                        "pid": int(entry),
                        "process": bin_base,
                        "exe": exe_target,
                        "cmdline": parts[:25],
                        "has_arg": has_mitig,
                    })
                    rel_txt = _read_jdk_release_version(exe_target)
                    if rel_txt:
                        detected_versions.append((f"running process PID {entry} ({exe_target})", rel_txt))
        except Exception:
            pass

    # 3. Scan standard JVM directories (/usr/lib/jvm, /opt, JAVA_HOME) for <jdk>/release files
    jvm_roots = ["/usr/lib/jvm", "/opt/java", "/opt/jdk", "/usr/java", "/Library/Java/JavaVirtualMachines"]
    env_java_home = os.environ.get("JAVA_HOME")
    if env_java_home:
        rel_txt = _read_jdk_release_version(env_java_home)
        if rel_txt:
            detected_versions.append((f"JAVA_HOME ({env_java_home})", rel_txt))

    for root_dir in jvm_roots:
        if not os.path.isdir(root_dir):
            continue
        try:
            for sub in sorted(os.listdir(root_dir)):
                sub_path = os.path.join(root_dir, sub)
                for candidate in (sub_path, os.path.join(sub_path, "Contents", "Home")):
                    rel_txt = _read_jdk_release_version(candidate)
                    if rel_txt:
                        detected_versions.append((f"{candidate}/release", rel_txt))
        except Exception:
            continue

    # 4. Also check Debian/Ubuntu /var/lib/dpkg/status for installed openjdk packages
    dpkg_status = _read_text_file_safe("/var/lib/dpkg/status", 2 * 1024 * 1024)
    if dpkg_status:
        for block in dpkg_status.split("\n\n"):
            if "Package: openjdk-" in block or "Package: temurin-" in block or "Package: oracle-java" in block:
                if "Status: install ok installed" in block:
                    pkg_m = re.search(r"^Package:\s*(.+)$", block, re.MULTILINE)
                    ver_m = re.search(r"^Version:\s*(.+)$", block, re.MULTILINE)
                    if pkg_m and ver_m:
                        detected_versions.append((f"dpkg package {pkg_m.group(1).strip()}", ver_m.group(1).strip()))

    return {
        "mode": "local_direct",
        "cpu_model": cpu_model,
        "cpu_flags": cpu_flags,
        "has_avx512vbmi": has_avx512vbmi,
        "java_processes": java_processes,
        "detected_versions": detected_versions,
    }


class OpenJDKCVE2026114938AuditPlugin(BasePlugin):
    """
    RTMS External Plugin & Standalone Auditor for CVE-2026-114938 (OpenJDK AVX-512 VBMI Base64 Heap Overflow).
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "OpenJDK / Oracle Java SE AVX-512 VBMI Base64 Heap Overflow Audit (CVE-2026-114938)",
            "description": (
                "Verifies whether a host runs an OpenJDK / Oracle Java SE version affected by CVE-2026-114938 "
                "(CVSS 8.1 High) AND checks hardware AVX-512 VBMI support ('avx512vbmi') and JVM '-XX:UseAVX=2' "
                "mitigation via the generic RTMS Local Agent API or direct local CLI inspection."
            ),
            "severity": "High",
            "cve": "CVE-2026-114938",
        }
        self.agent_port = DEFAULT_AGENT_PORT
        self.timeout = 4.0

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        In RTMS Scanner mode, checks if the RTMS Local Agent port (12000) is open on target_ip.
        """
        if isinstance(target_services, (list, set, tuple, dict)):
            if self.agent_port in target_services:
                return True

        # Quick TCP probe on port 12000 in case target_services did not include 12000
        try:
            with socket.create_connection((target_ip, self.agent_port), timeout=1.5):
                return True
        except Exception:
            return False

    def inspect_via_local_agent(self, target_ip: str, port: int = DEFAULT_AGENT_PORT) -> Optional[Dict[str, Any]]:
        """
        Queries the generic RTMS Local Agent on TCP port 12000 using POST /api/audit/inspect
        (with automatic fallback to GET /api/inventory).
        """
        payload = {
            "queries": [
                {"id": "cpu_flag", "query_type": "cpu_has_flag", "flag": "avx512vbmi"},
                {"id": "jvm_arg", "query_type": "process_has_arg", "process": "java", "arg": "-XX:UseAVX=2"},
                {"id": "java_bin", "query_type": "binary_version", "binary": "java"},
                {"id": "java_pkg", "query_type": "package_version", "package": "jdk"},
            ]
        }

        conn: Optional[http.client.HTTPConnection] = None
        try:
            conn = http.client.HTTPConnection(target_ip, port, timeout=self.timeout)
            body = json.dumps(payload).encode("utf-8")
            conn.request(
                "POST",
                "/api/audit/inspect",
                body=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            resp = conn.getresponse()
            raw_data = resp.read(524288).decode("utf-8", errors="ignore")

            if resp.status == 200 and raw_data:
                parsed = json.loads(raw_data)
                results_map = {r.get("id"): r for r in (parsed.get("results") or []) if isinstance(r, dict)}

                cpu_res = results_map.get("cpu_flag") or {}
                jvm_res = results_map.get("jvm_arg") or {}
                bin_res = results_map.get("java_bin") or {}
                pkg_res = results_map.get("java_pkg") or {}

                detected_versions: List[Tuple[str, str]] = []
                if bin_res.get("version_output"):
                    detected_versions.append(("agent binary_version(java)", str(bin_res["version_output"])))
                for pkg_name, pkg_ver in (pkg_res.get("packages") or {}).items():
                    detected_versions.append((f"agent package ({pkg_name})", str(pkg_ver)))
                for proc in jvm_res.get("processes") or []:
                    pver = proc.get("version")
                    if pver and pver != "local/untracked":
                        detected_versions.append((f"running process ({proc.get('process')})", str(pver)))

                return {
                    "mode": f"remote_agent ({target_ip}:{port}/api/audit/inspect)",
                    "cpu_model": cpu_res.get("cpu_model") or "Unknown CPU",
                    "has_avx512vbmi": bool(cpu_res.get("matched", False)),
                    "java_processes": jvm_res.get("processes") or [],
                    "detected_versions": detected_versions,
                }
        except Exception as exc:
            logger.debug("POST /api/audit/inspect failed on %s:%s: %s", target_ip, port, exc)
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        # Fallback: GET /api/inventory + GET /api/host
        try:
            conn = http.client.HTTPConnection(target_ip, port, timeout=self.timeout)
            conn.request("GET", "/api/inventory", headers={"Accept": "application/json"})
            resp = conn.getresponse()
            inv_raw = resp.read(524288).decode("utf-8", errors="ignore")
            if resp.status != 200 or not inv_raw:
                return None
            inv_data = json.loads(inv_raw)

            conn.request("GET", "/api/host", headers={"Accept": "application/json"})
            resp_h = conn.getresponse()
            host_raw = resp_h.read(262144).decode("utf-8", errors="ignore")
            host_data = json.loads(host_raw) if (resp_h.status == 200 and host_raw) else {}

            cpu_flags = [str(f).lower() for f in (host_data.get("cpu_flags") or [])]
            has_vbmi = "avx512vbmi" in cpu_flags
            cpu_model = host_data.get("cpu_model") or "Unknown CPU"

            detected_versions = []
            for pkg_name, pkg_ver in (inv_data.get("installed_packages") or {}).items():
                if any(k in pkg_name.lower() for k in ("jdk", "jre", "java", "temurin", "graalvm")):
                    detected_versions.append((f"installed_package ({pkg_name})", str(pkg_ver)))

            java_procs = []
            proc_details = inv_data.get("running_processes_details") or {}
            for pname, pinfo in proc_details.items():
                if "java" in pname.lower():
                    cmdline = pinfo.get("cmdline") or []
                    java_procs.append({
                        "process": pname,
                        "version": pinfo.get("version"),
                        "cmdline": cmdline,
                        "has_arg": _has_avx_mitigation_flag(cmdline),
                    })

            return {
                "mode": f"remote_agent_inventory ({target_ip}:{port}/api/inventory)",
                "cpu_model": cpu_model,
                "has_avx512vbmi": has_vbmi,
                "java_processes": java_procs,
                "detected_versions": detected_versions,
            }
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def evaluate_host_posture(self, target_label: str, facts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Applies the 3-dimensional CVE-2026-114938 decision matrix:
          1. OpenJDK / Java SE version in affected range
          2. CPU hardware support for 'avx512vbmi'
          3. JVM runtime mitigation flag '-XX:UseAVX=2'
        """
        mode = facts.get("mode", "unknown")
        cpu_model = facts.get("cpu_model", "Unknown CPU")
        has_vbmi = bool(facts.get("has_avx512vbmi", False))
        java_procs = facts.get("java_processes") or []
        detected_versions: List[Tuple[str, str]] = facts.get("detected_versions") or []

        vulnerable_versions: List[str] = []
        safe_versions: List[str] = []

        for source, ver_text in detected_versions:
            parsed = parse_openjdk_version(ver_text)
            if not parsed:
                continue
            ver_tuple, raw_ver = parsed
            is_vuln, reason = is_openjdk_version_vulnerable(ver_tuple, raw_ver)
            entry = f"{source}: {raw_ver} ({reason})"
            if is_vuln:
                vulnerable_versions.append(entry)
            else:
                safe_versions.append(entry)

        if not vulnerable_versions and not safe_versions and not java_procs:
            return self.format_result(
                "OK",
                proof=f"Source: {mode} | CPU: {cpu_model} (avx512vbmi={has_vbmi})",
                details=f"No OpenJDK / Oracle Java SE installation or running JVM process detected on {target_label}.",
            )

        if not vulnerable_versions:
            proof = (
                f"Source: {mode}\n"
                f"CPU: {cpu_model} (avx512vbmi={has_vbmi})\n"
                f"Detected Java versions:\n  - " + "\n  - ".join(safe_versions or ["No affected version found"])
            )
            return self.format_result(
                "OK",
                proof=proof,
                details=f"Safe: OpenJDK / Java installations on {target_label} are not in CVE-2026-114938 affected ranges.",
            )

        # At least one Java installation/process is in the affected version range!
        # Check Hardware Prerequisite (AC:H -> avx512vbmi)
        if not has_vbmi:
            proof = (
                f"Source: {mode}\n"
                f"CPU: {cpu_model} | avx512vbmi Hardware Flag: FALSE (Not Supported)\n"
                f"Affected Software Installed:\n  - " + "\n  - ".join(vulnerable_versions)
            )
            details = (
                f"MITIGATED BY HARDWARE (Non-Exploitable on {target_label}):\n"
                f"Although an affected OpenJDK / Java version is present, the host processor ({cpu_model}) "
                f"does NOT support the 'avx512vbmi' instruction set extension. The HotSpot C2 JIT compiler "
                f"never activates the vulnerable AVX-512 VBMI Base64 decoding intrinsic on this CPU.\n"
                f"Updating OpenJDK to >= 17.0.22 / 21.0.14 / 25.0.6 is still recommended for hygiene."
            )
            return self.format_result("OK", proof=proof, details=details)

        # CPU HAS avx512vbmi! Check if running JVM processes all have -XX:UseAVX=2 mitigation
        unmitigated_procs = [p for p in java_procs if not p.get("has_arg")]
        if java_procs and not unmitigated_procs:
            proof = (
                f"Source: {mode}\n"
                f"CPU: {cpu_model} | avx512vbmi: TRUE\n"
                f"JVM Runtime Mitigation: ACTIVE (-XX:UseAVX<=2 verified on {len(java_procs)} running JVM process(es))\n"
                f"Affected Software:\n  - " + "\n  - ".join(vulnerable_versions)
            )
            details = (
                f"MITIGATED BY JVM FLAG (-XX:UseAVX=2) on {target_label}:\n"
                f"The host CPU supports 'avx512vbmi' and runs an affected OpenJDK version, but all active "
                f"JVM processes enforce '-XX:UseAVX=2' (or lower), disabling the vulnerable AVX-512 VBMI intrinsic."
            )
            return self.format_result("OK", proof=proof, details=details)

        # Both vulnerable software AND avx512vbmi CPU are present without -XX:UseAVX=2 mitigation!
        proc_summary = (
            f"{len(unmitigated_procs)} active JVM process(es) running WITHOUT -XX:UseAVX=2"
            if unmitigated_procs
            else "No -XX:UseAVX=2 runtime mitigation detected"
        )
        proof = (
            f"CVE-2026-114938 ('Java4Shell') EXPLOITABLE CONDITIONS MET on {target_label}:\n"
            f"- Inspection Source: {mode}\n"
            f"- Processor: {cpu_model} (avx512vbmi = TRUE)\n"
            f"- Runtime Status: {proc_summary}\n"
            f"- Affected Java Instances:\n  * " + "\n  * ".join(vulnerable_versions)
        )
        details = (
            f"HIGH SEVERITY FINDING — CVE-2026-114938 (CVSS v3.1 8.1 High):\n"
            f"Host {target_label} meets ALL software and hardware conditions for CVE-2026-114938 "
            f"(HotSpot C2 JIT compiler heap buffer overflow in java.util.Base64 AVX-512 VBMI intrinsic).\n\n"
            f"Technical Evidence:\n"
            f"1. Affected OpenJDK / Java SE version detected:\n   - " + "\n   - ".join(vulnerable_versions) + "\n"
            f"2. Processor '{cpu_model}' exposes the 'avx512vbmi' instruction set flag.\n"
            f"3. {proc_summary}.\n\n"
            f"Remediation:\n"
            f"1. Immediate Workaround (No code change): Add '-XX:UseAVX=2' to JVM startup flags (JAVA_TOOL_OPTIONS).\n"
            f"2. Permanent Fix: Upgrade OpenJDK / Oracle Java SE to >= 17.0.22, >= 21.0.14, >= 25.0.6, or >= 27.0.2."
        )
        return self.format_result("Vulnerable", proof=proof, details=details)

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Entry point invoked by RTMS Scanner: queries the generic RTMS Local Agent on target_ip:12000.
        """
        facts = self.inspect_via_local_agent(target_ip, self.agent_port)
        if not facts:
            return self.format_result(
                "Skipped",
                proof=f"Target: {target_ip}:{self.agent_port}",
                details=f"Could not reach RTMS Local Agent inspection endpoint on {target_ip}:{self.agent_port}.",
            )
        return self.evaluate_host_posture(target_ip, facts)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description=(
            "Standalone & RTMS External Auditor for CVE-2026-114938 (OpenJDK AVX-512 VBMI Base64 Heap Overflow). "
            "When run without arguments (or with --local), audits the local server directly without needing "
            "rtms-local-agent. When given a remote IP/hostname, queries the remote rtms-local-agent on port 12000."
        )
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Optional remote target IP/hostname running rtms-local-agent (omit to audit the local server directly)",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Force direct local host inspection on this server without calling rtms-local-agent",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_AGENT_PORT,
        help=f"RTMS Local Agent TCP port for remote mode (default: {DEFAULT_AGENT_PORT})",
    )

    args = parser.parse_args()
    plugin = OpenJDKCVE2026114938AuditPlugin()
    plugin.agent_port = args.port

    if args.local or not args.target:
        local_facts = inspect_local_host_directly()
        result = plugin.evaluate_host_posture("localhost (direct CLI inspection)", local_facts)
    else:
        agent_facts = plugin.inspect_via_local_agent(args.target, args.port)
        if not agent_facts and args.target in ("127.0.0.1", "localhost", "::1"):
            local_facts = inspect_local_host_directly()
            result = plugin.evaluate_host_posture("localhost (fallback direct CLI inspection)", local_facts)
        elif not agent_facts:
            print(f"[-] Unable to reach RTMS Local Agent at {args.target}:{args.port}")
            sys.exit(2)
        else:
            result = plugin.evaluate_host_posture(args.target, agent_facts)

    status = result.get("status", "Unknown")
    print(f"[{status.upper()}] {result.get('plugin')}")
    if result.get("proof"):
        print("\n--- Proof ---")
        print(result["proof"])
    if result.get("details"):
        print("\n--- Details ---")
        print(result["details"])

    sys.exit(1 if status == "Vulnerable" else 0)
