# WordPress Tribulant Newsletters Object Injection & SQLi Auditor (CVE-2026-129039)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--129039-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Tribulant Newsletters (`newsletters-lite`)** (`<= 4.18.2`) against critical PHP object injection and SQL injection vulnerabilities (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-129039** (`CVSS 9.8 Critical`): Deserialization of untrusted data in `newsletters-lite` through version `4.18.2`.
* **CVE-2026-129043** (`CVSS 9.3 Critical`): SQL injection vulnerability in `newsletters-lite` through version `4.18.2`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Tribulant Newsletters (`newsletters-lite`)** | `<= 4.18.2` (`< 4.18.3`) | `>= 4.18.3` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_newsletters_lite/wp_newsletters_lite_cve_2026_129039_audit.py wp.internal.corp -p 80 443
```
