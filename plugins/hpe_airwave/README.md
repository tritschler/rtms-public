# HPE Networking Management Software (AirWave) Multi-CVE Compliance Auditor (CVE-2026-133973 / CVE-2026-133971)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--133971..133973-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **HPE Networking Management Software (AirWave)** (`8.3.0.0`–`8.3.0.7`) against 3 critical command injection and authentication bypass vulnerabilities (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-133973** (`CVSS 9.8 Critical`): Unauthenticated command injection in the web-based management interface of HPE Networking Management Software (AirWave).
* **CVE-2026-133972** (`CVSS 9.8 Critical`): Authentication bypass vulnerability in system functionality of HPE Networking Management Software (AirWave).
* **CVE-2026-133971** (`CVSS 9.8 Critical`): Unauthenticated authentication bypass in the web management interface of HPE Networking Management Software (AirWave).

---

## 📋 Affected Versions & Remediation Matrix

| Product | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **HPE Networking Management Software (AirWave)** | `8.3.0.0` – `8.3.0.7` (`< 8.3.0.8`) | `>= 8.3.0.8` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/hpe_airwave/hpe_airwave_cve_2026_133973_audit.py airwave.internal.corp -p 443 8443
```
