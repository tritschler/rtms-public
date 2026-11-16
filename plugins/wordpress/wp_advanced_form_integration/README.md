# WordPress Advanced Form Integration Privilege Escalation Audit (CVE-2026-125769)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Advanced Form Integration** installations against **CVE-2026-125769** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-125769** (`CVSS 9.8 Critical`): Incorrect privilege assignment vulnerability in the Advanced Form Integration WordPress plugin (`<= 2.11.3`) allowing privilege escalation.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Advanced Form Integration** | `<= 2.11.3 (< 2.11.4)` | `>= 2.11.4` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_advanced_form_integration/wp_advanced_form_integration_cve_2026_125769_audit.py wp.example.com -p 80 443
```
