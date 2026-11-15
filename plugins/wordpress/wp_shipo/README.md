# WordPress Shipo Authentication Bypass Audit (CVE-2026-19907)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Shipo** installations against **CVE-2026-19907** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-19907** (`CVSS 9.8 Critical`): Authentication bypass in REST API user verification in the Shipo WordPress plugin (`1.6` through `1.8.0`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Shipo** | `1.6 through 1.8.0 (< 1.8.1)` | `>= 1.8.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_shipo/wp_shipo_cve_2026_19907_audit.py wp.example.com -p 80 443
```
