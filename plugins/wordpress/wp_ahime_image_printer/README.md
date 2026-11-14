# WordPress Ahime Image Printer File Upload Validation Audit (CVE-2026-124833)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Ahime Image Printer** installations against **CVE-2026-124833** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-124833** (`CVSS 9.8 Critical`): Missing file name, extension, and type validation in the Ahime Image Printer WordPress plugin.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Ahime Image Printer** | `<= 1.0.0 (< 1.0.1)` | `>= 1.0.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_ahime_image_printer/wp_ahime_image_printer_cve_2026_124833_audit.py wp.example.com -p 80 443
```
