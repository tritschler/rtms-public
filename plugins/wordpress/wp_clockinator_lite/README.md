# WordPress Clockinator Lite SQL Injection & Access Control Auditor (CVE-2026-124815)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--124815-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Clockinator Lite** installations against **CVE-2026-124815** (`CVSS 10.0`).

---

## 🔍 Advisory Overview

* **CVE-2026-124815** (`CVSS 10.0 Critical`): Clockinator Lite before `1.1.0` lacks authorization checks on record deletion actions and fails to validate or escape table names in SQL queries.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Clockinator Lite** | `< 1.1.0` (`<= 1.0.9`) | `>= 1.1.0` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_clockinator_lite/wp_clockinator_lite_cve_2026_124815_audit.py wp.example.com -p 80 443
```
