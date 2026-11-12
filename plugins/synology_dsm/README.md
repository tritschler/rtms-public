# Synology DiskStation Manager (DSM) Version Compliance Auditor (CVE-2026-76954)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--76954-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Synology DiskStation Manager (DSM)** appliances against **CVE-2026-76954**.

---

## 🔍 Advisory Overview

* **CVE-2026-76954** (`CVSS 9.8 Critical`): Improper neutralization of special elements used in an SQL command (SQL Injection) in the Synology DSM Auth API.

---

## 📋 Affected Versions & Remediation Matrix

| DSM Branch | Affected Versions | Patched Version |
|:---:|:---:|:---:|
| **7.4** | `< 7.4.1-90080-1` | `>= 7.4.1-90080-1` |
| **7.3** | `< 7.3.2-86009-5` | `>= 7.3.2-86009-5` |
| **7.2.2** | `< 7.2.2-72806-10` | `>= 7.2.2-72806-10` |
| **7.2.1** | `< 7.2.1-69057-13` | `>= 7.2.1-69057-13` |
| **< 7.2.1** | All earlier releases | Upgrade to patched branch |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (uses Python standard library `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/synology_dsm/synology_dsm_cve_2026_76954_audit.py nas.internal.corp -p 5000 5001 443
```

### Exit Codes
* **`0`**: Host is compliant or no affected Synology DSM service detected.
* **`1`**: Affected Synology DSM version detected.

---

## 💡 Remediation
1. **Update DSM**: Upgrade Synology DiskStation Manager to `7.2.1-69057-13+`, `7.2.2-72806-10+`, `7.3.2-86009-5+`, or `7.4.1-90080-1+`.
2. **Restrict Management Access**: Limit external network exposure of DSM administrative ports (`5000/TCP` and `5001/TCP`).
