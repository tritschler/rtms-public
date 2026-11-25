# Joomla! CMS Multi-CVE Version Compliance Auditor (CVE-2026-129393 / CVE-2026-123214 / CVE-2026-126045 / CVE-2026-127297)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.4_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--129393-orange.svg)]()

A passive, read-only version compliance audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Joomla! CMS** deployments against the November 2026 Joomla! Core security advisories (**CVE-2026-129393**, **CVE-2026-123214**, **CVE-2026-126045**, and **CVE-2026-127297**).

---

## 🔍 Advisory Overview

* **CVE-2026-129393** (`CVSS v4.0: 9.4 Critical`): Inadequate escaping of media custom field parameters in generated form XML (`4.0.0–5.4.10`, `6.0.0–6.2.0`).
* **CVE-2026-123214** (`CVSS v4.0: 9.2 Critical`): Missing authentication in web installer (`4.0.0–5.4.10`, `6.0.0–6.2.0`).
* **CVE-2026-126045** (`CVSS v4.0: 9.2 Critical`): Local file inclusion through unvalidated language parameter (`1.6.0–5.4.10`, `6.0.0–6.2.0`).
* **CVE-2026-127297** (`CVSS v4.0: 9.2 Critical`): Race condition in formatted text logger (`3.6.0–5.4.10`, `6.0.0–6.2.0`).

---

## 📋 Affected & Patched Versions

| Component | Affected Versions | Patched / Safe Release |
|:---|:---:|:---:|
| **Joomla! CMS 1.6.x – 5.x** | `1.6.0` – `5.4.10` (`< 5.4.11`) | **`5.4.11+`** |
| **Joomla! CMS 6.x** | `6.0.0` – `6.2.0` (`< 6.2.1`) | **`6.2.1+`** |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/joomla/joomla_cve_2026_129393_audit.py cms.example.com -p 80 443 8080
```
