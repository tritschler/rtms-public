# phpMyFAQ Version Compliance Audit (`CVE-2026-130369` / `CVE-2026-130371`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **phpMyFAQ** installations (`< 4.1.12` and `4.2.0-alpha` before `4.2.0-RC.2`) against **CVE-2026-130369** and **CVE-2026-130371** (`CVSS 9.2`).

---

## 🔍 Advisory Overview

* **CVE-2026-130369** (`CVSS v4.0: 9.2 Critical`): Authorization bypass in multisite deployments via a shared PHP session store in phpMyFAQ `4.1.9` before `4.1.12` and `4.2.0-alpha` before `4.2.0-RC.2`.
* **CVE-2026-130371** (`CVSS v4.0: 9.2 Critical`): Authentication bypass in the web installer during 3.x upgrade workflows in phpMyFAQ before `4.1.12` and `4.2.0-alpha` before `4.2.0-RC.2`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **phpMyFAQ 4.1.x & earlier** | `< 4.1.12` | `>= 4.1.12` |
| **phpMyFAQ 4.2.x** | `4.2.0-alpha` – `< 4.2.0-RC.2` | `>= 4.2.0-RC.2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/phpmyfaq/phpmyfaq_cve_2026_130369_audit.py faq.example.com -p 80 443
```
