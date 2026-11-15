# WordPress Cloud Storage Manager for Fluent Forms File Write Audit (CVE-2026-120522)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Cloud Storage Manager for Fluent Forms** installations against **CVE-2026-120522** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-120522** (`CVSS 9.8 Critical`): Missing authorization checks and insufficient path validation in the Cloud Storage Manager for Fluent Forms WordPress plugin (`<= 1.2.0`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Cloud Storage Manager for Fluent Forms** | `<= 1.2.0 (< 1.2.1)` | `>= 1.2.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_fluent_forms_cloud_storage/wp_fluent_forms_cloud_storage_cve_2026_120522_audit.py wp.example.com -p 80 443
```
