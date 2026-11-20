# WordPress WP Duplicate Migration Plugin RCE Audit (CVE-2026-14492)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WP Duplicate – WordPress Migration Plugin** installations against **CVE-2026-14492** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-14492** (`CVSS 9.8 Critical`): Authentication bypass and path traversal leading to Remote Code Execution via `save_single_batch_file` in WP Duplicate (`<= 1.1.11`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **WP Duplicate – WordPress Migration Plugin** | `<= 1.1.11` (`< 1.1.12`) | `>= 1.1.12` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_duplicate/wp_duplicate_cve_2026_14492_audit.py wp.example.com -p 80 443
```
