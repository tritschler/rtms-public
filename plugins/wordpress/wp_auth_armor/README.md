# WordPress Auth Armor Missing Authentication Audit (CVE-2026-110960)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Auth Armor** installations against **CVE-2026-110960** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-110960** (`CVSS 9.8 Critical`): Missing authentication on handlers available to unauthenticated users in the Auth Armor WordPress plugin (`<= 1.0.3`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Auth Armor** | `<= 1.0.3 (< 1.0.4)` | `>= 1.0.4` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_auth_armor/wp_auth_armor_cve_2026_110960_audit.py wp.example.com -p 80 443
```
