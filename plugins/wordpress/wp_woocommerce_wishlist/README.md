# WordPress Woocommerce Wishlist Missing Authorization & CSRF Audit (CVE-2026-124763)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Woocommerce Wishlist** installations against **CVE-2026-124763** (`CVSS 9.1`).

---

## 🔍 Advisory Overview

* **CVE-2026-124763** (`CVSS 9.1 Critical`): Missing authorization and CSRF checks on unauthenticated AJAX actions in Woocommerce Wishlist <= 1.1.0.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Woocommerce Wishlist** | `<= 1.1.0 (< 1.1.1)` | `>= 1.1.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_woocommerce_wishlist/wp_woocommerce_wishlist_cve_2026_124763_audit.py wp.example.com -p 80 443
```
