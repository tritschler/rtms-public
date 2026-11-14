# WordPress AutomatorWP Pro Webhook Auth Bypass Audit (CVE-2026-126173)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress AutomatorWP Pro Webhooks Addon** installations against **CVE-2026-126173** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-126173** (`CVSS 9.8 Critical`): Authorization bypass in the AutomatorWP Pro webhook addon allowing unauthorized account password resets.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **AutomatorWP Pro Webhooks Addon** | `<= 1.4.4 (< 1.4.5)` | `>= 1.4.5` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_automatorwp_pro/wp_automatorwp_pro_cve_2026_126173_audit.py wp.example.com -p 80 443
```
