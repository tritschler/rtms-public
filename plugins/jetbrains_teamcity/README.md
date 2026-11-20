# JetBrains TeamCity Multi-CVE Version Compliance Auditor (CVE-2026-132234 / CVE-2026-132891)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--132234_%2F_CVE--2026--132891-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **JetBrains TeamCity** (`< 2025.11.8` and `2026.1.0`–`2026.1.3`) against 5 critical Remote Code Execution vulnerabilities (`CVSS 9.8`–`9.9`).

---

## 🔍 Advisory Overview

* **CVE-2026-132234** (`CVSS 9.9 Critical`): Remote Code Execution via argument injection in Mercurial VCS root settings (`< 2025.11.7`, `2026.1.x < 2026.1.3`).
* **CVE-2026-132233** (`CVSS 9.9 Critical`): Remote Code Execution via build attribute injection (`< 2025.11.7`, `2026.1.x < 2026.1.3`).
* **CVE-2026-132232** (`CVSS 9.9 Critical`): Remote Code Execution via argument injection in Perforce settings (`< 2025.11.7`, `2026.1.x < 2026.1.3`).
* **CVE-2026-132231** (`CVSS 9.9 Critical`): Remote Code Execution via best-fit character mapping in Perforce settings (`< 2025.11.7`, `2026.1.x < 2026.1.3`).
* **CVE-2026-132891** (`CVSS 9.8 Critical`): Remote Code Execution via external pull requests (`< 2025.11.8`, `2026.1.x < 2026.1.4`, `< 2026.2`).

---

## 📋 Affected Versions & Remediation Matrix

| Product | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **JetBrains TeamCity (2025.11.x & earlier)** | `< 2025.11.8` | `>= 2025.11.8` |
| **JetBrains TeamCity (2026.1.x)** | `2026.1.0` – `2026.1.3` (`< 2026.1.4`) | `>= 2026.1.4` / `>= 2026.2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/jetbrains_teamcity/jetbrains_teamcity_cve_2026_132234_audit.py ci.internal.corp -p 8111 443 8443
```
