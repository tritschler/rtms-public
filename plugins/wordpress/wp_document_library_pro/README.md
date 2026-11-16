# WordPress Document Library Pro Object Injection Audit (CVE-2026-122662)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Document Library Pro** installations against **CVE-2026-122662** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-122662** (`CVSS 9.8 Critical`): Deserialization of untrusted data vulnerability (PHP Object Injection) in Barn2 Plugins Document Library Pro (`< 4.2.2`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Document Library Pro** | `< 4.2.2 (<= 4.2.1)` | `>= 4.2.2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_document_library_pro/wp_document_library_pro_cve_2026_122662_audit.py wp.example.com -p 80 443
```
