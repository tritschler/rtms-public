# SAP Web Dispatcher & NetWeaver Compliance Auditor (CVE-2026-89126 / CVE-2026-76964)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--89126-orange.svg)]()

A passive, read-only version compliance audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **SAP Web Dispatcher**, **SAP NetWeaver Application Server ABAP (ICM)**, and **SAP Gateway** deployments against the November 2026 SAP Critical Advisories (`CVE-2026-89126`, `CVE-2026-76964`, `CVE-2026-89103`, `CVE-2026-120017`, `CVE-2026-76965`, `CVE-2026-89119`, `CVE-2026-109803`, and `CVE-2026-109795`).

---

## 🔍 Advisory Overview

* **Primary Advisories**:
  * **CVE-2026-89126** (`CVSS 10.0 Critical`): Insufficient network input validation in SAP Web Dispatcher (`7.53`, `7.54`, `7.77`, `7.93`, `9.16`, `9.18`, `9.20`).
  * **CVE-2026-76964** (`CVSS 10.0 Critical`): Insufficient network input validation in SAP NetWeaver AS ABAP Internet Communication Manager (`7.53`, `7.54`, `7.77`, `7.93`, `9.16`, `9.18`, `9.20`).
  * **CVE-2026-89103** (`CVSS 10.0 Critical`): Default permissive Access Control List (ACL) configuration in SAP Gateway (`7.22`, `7.53`, `7.54`, `7.77`, `7.93`, `8.04`, `9.16`, `9.20`, `9.21`).
  * **CVE-2026-120017** (`CVSS 10.0 Critical`): Insufficient verification of incoming authentication assertions in SAP NetWeaver AS ABAP SAML2 Service Provider (`SAP_BASIS 702`–`758`, `816`, `920`–`922`).
  * **CVE-2026-76965** (`CVSS 9.9 Critical`): Missing authorization check in SAP NetWeaver AS ABAP (`7.22`–`9.16`).
  * **CVE-2026-89119** (`CVSS 9.6 Critical`): Request validation deficiency in SAP Web Dispatcher and ICM administrative interfaces (`7.93`, `9.16`, `9.20`, `9.21`).

---

## 📋 Affected Release Branches

| SAP Component | Affected Release Branches | Remediation |
|:---|:---:|:---|
| **SAP Web Dispatcher (`WEBDISP`)** | `7.53`, `7.54`, `7.77`, `7.93`, `9.16`, `9.18`, `9.20`, `9.21` | Apply November 2026 SAP Security Patch Day Kernel/Web Dispatcher updates |
| **SAP NetWeaver AS ABAP (`ICM` / `KRNL64UC`)** | `7.22`, `7.53`, `7.54`, `7.77`, `7.93`, `8.04`, `9.16`, `9.18`, `9.20`, `9.21` | Upgrade SAP Kernel & `SAP_BASIS` Support Packages |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (standard Python library: `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/sap_netweaver/sap_netweaver_cve_2026_89126_audit.py sap.internal.corp -p 80 443 8000 8443 44300
```

### Exit Codes
* **`0`**: Host is compliant or no affected SAP HTTP service detected.
* **`1`**: Affected SAP kernel / Web Dispatcher branch detected requiring patch verification.

---

## 💡 Remediation
1. **Apply SAP Security Notes (November 2026 Patch Day)**: Update SAP Web Dispatcher, ICM, and SAP Kernel packages to the latest patch level.
2. **Harden SAP Gateway ACLs**: Configure `gw/acl_mode = 1` and enforce strict `secinfo` and `reginfo` rules.
3. **Restrict Management Interfaces**: Limit access to SAP Web Dispatcher administration ports to trusted management networks.
