# WordPress Descope Authentication Bypass Auditor (CVE-2026-110959)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--110959-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Descope** installations against **CVE-2026-110959** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-110959** (`CVSS 9.8 Critical`): The Descope WordPress plugin before `1.2.0` fails to validate the authentication token before creating a WordPress session, accepting any non-empty token.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Descope** | `< 1.2.0` (`<= 1.1.x`) | `>= 1.2.0` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_descope/wp_descope_cve_2026_110959_audit.py wp.example.com -p 80 443
```
