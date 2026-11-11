# Ivanti Endpoint Manager Version Compliance Auditor (CVE-2026-121653)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--121653-orange.svg)]()

A passive, read-only version compliance audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Ivanti Endpoint Manager (EPM)** Core servers against **CVE-2026-121653** and **CVE-2026-121683**.

---

## 🔍 Advisory Overview

* **CVE-2026-121653** (`CVSS 9.8 Critical`): SQL injection vulnerability in the Core of Ivanti Endpoint Manager prior to version `2024 SU8`.
* **CVE-2026-121683** (`CVSS 9.4 Critical`): Missing authentication in Ivanti Cloud Services Application (`CSA 5.0.8`) affecting EPM Core certificate entries.

---

## 📋 Affected Versions & Remediation Matrix

| Product | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Ivanti Endpoint Manager (EPM)** | `< 2024 SU8` (`< 11.0.6.8`), `2022.x` (`11.0.5.x`) | `>= 2024 SU8` (`11.0.6.8+`) |
| **Ivanti Cloud Services Application (CSA)** | `5.0.8` | `> 5.0.8` |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (uses Python standard library `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/ivanti_epm/ivanti_epm_cve_2026_121653_audit.py epm.internal.corp -p 443 80 8443
```

### Exit Codes
* **`0`**: Host is compliant or no affected Ivanti EPM service detected.
* **`1`**: Affected Ivanti EPM release detected.

---

## 💡 Remediation
1. **Apply Service Update**: Upgrade Ivanti Endpoint Manager to **2024 SU8** (`11.0.6.8`) or later.
2. **Restrict Core Web Services**: Limit access to the EPM Core web and management ports to managed endpoints and administrative networks.
3. **Update CSA**: Ensure paired Ivanti Cloud Services Application appliances are patched beyond version `5.0.8`.
