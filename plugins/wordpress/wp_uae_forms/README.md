# WordPress Ultimate Addons for Elementor Forms File Upload Auditor (CVE-2026-124814)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--124814-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Ultimate Addons for Elementor Forms** installations against **CVE-2026-124814** (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-124814** (`CVSS 9.8 Critical`): Ultimate Addons for Elementor Forms before `1.0.8` does not properly validate uploaded file extensions in its bundled file upload field.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Ultimate Addons for Elementor Forms** | `< 1.0.8` (`<= 1.0.7`) | `>= 1.0.8` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_uae_forms/wp_uae_forms_cve_2026_124814_audit.py wp.example.com -p 80 443
```
