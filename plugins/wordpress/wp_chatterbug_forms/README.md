# WordPress Chatterbug Forms File Upload Validation Audit (CVE-2026-125055)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Chatterbug Forms** installations against **CVE-2026-125055** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-125055** (`CVSS 9.8 Critical`): Missing server-side file extension validation in Chatterbug Forms <= 1.0.2.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Chatterbug Forms** | `<= 1.0.2 (< 1.0.3)` | `>= 1.0.3` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_chatterbug_forms/wp_chatterbug_forms_cve_2026_125055_audit.py wp.example.com -p 80 443
```
