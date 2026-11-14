# WordPress Advance Guest Post File Upload Validation Audit (CVE-2026-118063, CVE-2026-118064)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Advance Guest Post** installations against **CVE-2026-118063, CVE-2026-118064** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-118063, CVE-2026-118064** (`CVSS 9.8 Critical`): Improper file upload validation and extension check bypass in the Advance Guest Post WordPress plugin.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Advance Guest Post** | `<= 1.9 (< 1.9.1)` | `>= 1.9.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_advance_guest_post/wp_advance_guest_post_cve_2026_118063_audit.py wp.example.com -p 80 443
```
