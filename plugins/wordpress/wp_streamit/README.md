# WordPress Streamit Unauthenticated AJAX Authorization Audit (CVE-2026-126119)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Streamit** installations against **CVE-2026-126119** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-126119** (`CVSS 9.8 Critical`): Missing authorization and nonce verification on unauthenticated AJAX routes in the Streamit WordPress plugin.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Streamit** | `< 1.3.10 (<= 1.3.9)` | `>= 1.3.10` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_streamit/wp_streamit_cve_2026_126119_audit.py wp.example.com -p 80 443
```
