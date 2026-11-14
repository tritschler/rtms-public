# WordPress WP BASE Booking SQL Injection Compliance Audit (CVE-2026-124970)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress WP BASE Booking** installations against **CVE-2026-124970** (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-124970** (`CVSS 9.3 Critical`): Improper neutralization of special elements in SQL commands (Blind SQL Injection) in WP BASE Booking <= 6.5.2.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **WP BASE Booking** | `<= 6.5.2 (< 6.5.3)` | `>= 6.5.3` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_base_booking/wp_base_booking_cve_2026_124970_audit.py wp.example.com -p 80 443
```
