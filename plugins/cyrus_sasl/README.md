# Cyrus SASL SRP Authentication Bypass Compliance Auditor (CVE-2026-129483)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Patched->=_2.1.29-brightgreen.svg)]()

A passive, read-only version and capability compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Cyrus SASL** endpoints against **CVE-2026-129483** (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-129483** (`CVSS 9.3 Critical`): Cyrus SASL through `2.1.28` contains an authentication bypass vulnerability in the SRP server mechanism (`srp_server_mech_step2`).

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Releases | Patched Release / Mitigation |
|:---:|:---:|:---:|
| **Cyrus SASL (`libsasl2`)** | `<= 2.1.28` | `>= 2.1.29` (or disable `srp` SASL plugin) |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/cyrus_sasl/cyrus_sasl_cve_2026_129483_audit.py mail.internal.corp -p 25 110 143 465 587 993 995 4190
```
