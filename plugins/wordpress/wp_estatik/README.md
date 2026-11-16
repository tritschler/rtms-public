# WordPress Estatik Local File Inclusion Audit (CVE-2026-125795)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Estatik** installations against **CVE-2026-125795** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-125795** (`CVSS 9.8 Critical`): Improper control of filename for include/require statement in PHP program (Local File Inclusion) in the Estatik WordPress plugin (`<= 4.3.6`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Estatik** | `<= 4.3.6 (< 4.3.7)` | `>= 4.3.7` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_estatik/wp_estatik_cve_2026_125795_audit.py wp.example.com -p 80 443
```
