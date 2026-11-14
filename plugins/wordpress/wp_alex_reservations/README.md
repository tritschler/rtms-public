# WordPress Alex Reservations SQL Injection Compliance Audit (CVE-2026-124415)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Alex Reservations** installations against **CVE-2026-124415** (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-124415** (`CVSS 9.3 Critical`): Improper neutralization of special elements in SQL commands (SQL Injection) in Alex Reservations <= 2.4.8.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Alex Reservations** | `<= 2.4.8 (< 2.4.9)` | `>= 2.4.9` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_alex_reservations/wp_alex_reservations_cve_2026_124415_audit.py wp.example.com -p 80 443
```
