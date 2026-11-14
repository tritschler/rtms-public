# WordPress Hotel Booking Lite Unrestricted File Upload Audit (CVE-2026-125851)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Hotel Booking Lite** installations against **CVE-2026-125851** (`CVSS 9.9`).

---

## 🔍 Advisory Overview

* **CVE-2026-125851** (`CVSS 9.9 Critical`): Unrestricted upload of file with dangerous type in the Hotel Booking Lite WordPress plugin.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Hotel Booking Lite** | `<= 2.5.1 (< 2.5.2)` | `>= 2.5.2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_hotel_booking_lite/wp_hotel_booking_lite_cve_2026_125851_audit.py wp.example.com -p 80 443
```
