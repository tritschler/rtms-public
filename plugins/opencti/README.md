# OpenCTI Platform Version Compliance Audit (`CVE-2026-104840`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **OpenCTI Platform** installations (`< 7.260428.0`) against **CVE-2026-104840** (`CVSS 9.2`).

---

## 🔍 Advisory Overview

* **CVE-2026-104840** (`CVSS v4.0: 9.2 Critical`): Missing endpoint-specific rate limiting on the primary login GraphQL mutation in OpenCTI before `7.260428.0`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **OpenCTI Platform** | `< 7.260428.0` | `>= 7.260428.0` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/opencti/opencti_cve_2026_104840_audit.py opencti.example.com -p 80 443 4000 8080
```
