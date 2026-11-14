# WordPress ELEX HelpDesk PHP Object Injection Audit (CVE-2026-119077, CVE-2026-125855)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress ELEX WordPress HelpDesk & Customer Ticketing System** installations against **CVE-2026-119077, CVE-2026-125855** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-119077, CVE-2026-125855** (`CVSS 9.8 Critical`): Untrusted data deserialization (PHP Object Injection) in ELEX WordPress HelpDesk & Customer Ticketing System.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **ELEX WordPress HelpDesk & Customer Ticketing System** | `<= 3.3.9 (< 3.3.10)` | `>= 3.3.10` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_elex_helpdesk/wp_elex_helpdesk_cve_2026_119077_audit.py wp.example.com -p 80 443
```
