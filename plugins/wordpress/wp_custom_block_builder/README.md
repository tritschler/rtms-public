# WordPress Custom Block Builder REST Authorization Audit (CVE-2026-127048)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Custom Block Builder** installations against **CVE-2026-127048** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-127048** (`CVSS 9.8 Critical`): Improper permission validation on REST routes in the Custom Block Builder WordPress plugin (`< 3.0.0`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Custom Block Builder** | `< 3.0.0` | `>= 3.0.0` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_custom_block_builder/wp_custom_block_builder_cve_2026_127048_audit.py wp.example.com -p 80 443
```
