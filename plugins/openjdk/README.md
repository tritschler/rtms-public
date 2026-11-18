# OpenJDK / Oracle Java SE AVX-512 VBMI Base64 Heap Overflow Auditor (CVE-2026-114938)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-8.1_HIGH-orange.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--114938-red.svg)]()

A defensive, read-only compliance tool and official external plugin for **[RTMS Suite](https://3ts.ai)** to verify **OpenJDK**, **Oracle Java SE**, and **Oracle GraalVM** instances against **CVE-2026-114938** ("Java4Shell" — HotSpot C2 JIT compiler AVX-512 VBMI Base64 decoding heap buffer overflow).

---

## 🔍 Advisory Overview

* **CVE-2026-114938** (`CVSS 8.1 High` — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`):
  A heap buffer overflow (62–63 bytes out-of-bounds write) in the HotSpot C2 JIT compiler intrinsic for `java.util.Base64` decoding (`decodeBlock`).
* **3-Dimensional Exploitability Matrix**:
  1. **Software Version**: OpenJDK / Oracle Java SE / GraalVM in affected branches (`17.0.6`–`17.0.21.0.3`, `21.0.0`–`21.0.13.0.3`, `25.0.0`–`25.0.5.0.3`, `27.0.0`–`27.0.1.0.3`).
  2. **Hardware Prerequisite (`AC:H`)**: Host `x86_64` CPU must support the **`avx512vbmi`** instruction set extension.
  3. **JVM Runtime Mitigation**: Absence of the **`-XX:UseAVX=2`** (or lower) JVM startup flag.

---

## 📋 Affected Versions & Remediation Matrix

| Branch | Affected Versions | Patched Version | Immediate Workaround |
|:---|:---:|:---:|:---:|
| **Java 17 LTS** | `17.0.6` – `17.0.21.0.3` | `>= 17.0.22` | `-XX:UseAVX=2` |
| **Java 21 LTS** | `21.0.0` – `21.0.13.0.3` | `>= 21.0.14` | `-XX:UseAVX=2` |
| **Java 25 LTS** | `25.0.0` – `25.0.5.0.3` | `>= 25.0.6` | `-XX:UseAVX=2` |
| **Java 27** | `27.0.0` – `27.0.1.0.3` | `>= 27.0.2` | `-XX:UseAVX=2` |

---

## 🚀 Usage

### 1. Standalone CLI on the Server Itself (No Agent Needed)
Run directly on a Linux/Unix server to inspect `/proc/cpuinfo`, active JVM processes (`/proc/<pid>/cmdline`), `<JAVA_HOME>/release` files, and installed packages:

```bash
python3 plugins/openjdk/openjdk_cve_2026_114938_audit.py
# or explicitly:
python3 plugins/openjdk/openjdk_cve_2026_114938_audit.py --local
```

### 2. Remote Audit via RTMS Local Agent (Port 12000) or Inside RTMS Scanner
When executed by `rtms-scanner` or passed a remote IP/hostname, the plugin queries the generic `POST /api/audit/inspect` endpoint of `rtms-local-agent`:

```bash
python3 plugins/openjdk/openjdk_cve_2026_114938_audit.py 192.168.1.50 -p 12000
```
