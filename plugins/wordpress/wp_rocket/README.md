# WordPress WP Rocket Path Traversal Auditor (CVE-2026-125812)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--125812-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WP Media WP Rocket** (`< 3.24.2`) against a critical Path Traversal vulnerability (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-125812** (`CVSS 9.8 Critical`): Improper Limitation of a Pathname to a Restricted Directory (`Path Traversal`) vulnerability in **WP Media WP Rocket** (`wp-rocket`) prior to version `3.24.2`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **WP Media WP Rocket (`wp-rocket`)** | `< 3.24.2` (`<= 3.24.1`) | `>= 3.24.2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_rocket/wp_rocket_cve_2026_125812_audit.py wp.internal.corp -p 80 443
```
