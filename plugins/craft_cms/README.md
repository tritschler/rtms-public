# Craft CMS Version Compliance Auditor (CVE-2026-115934)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--115934-orange.svg)]()

A passive, read-only version compliance audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Craft CMS** deployments against **CVE-2026-115934** (SQL Injection in `craft.search` affecting Craft CMS `< 4.18.9` and `< 5.11.2`).

---

## 🔍 Advisory Overview

* **CVE ID**: `CVE-2026-115934`
* **Severity**: **Critical (CVSS v4.0: 9.3)**
* **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
* **Affected Ecosystems**: Craft CMS 4.x (`4.0.0` before `4.18.9`) and 5.x (`5.0.0` before `5.11.2`) backed by MySQL or MariaDB.

---

## 📋 Affected & Patched Versions

| Component | Affected Versions | Patched / Safe Release |
|:---|:---:|:---:|
| **Craft CMS 4.x** | `4.0.0` – `4.18.8` (`< 4.18.9`) | **`4.18.9+`** |
| **Craft CMS 5.x** | `5.0.0` – `5.11.1` (`< 5.11.2`) | **`5.11.2+`** |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (standard Python library: `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/craft_cms/craft_cms_cve_2026_115934_audit.py cms.example.com -p 80 443 8080
```

### Exit Codes
* **`0`**: Host is compliant (`>= 4.18.9` / `>= 5.11.2`) or no Craft CMS instance detected.
* **`1`**: Affected Craft CMS version (`< 4.18.9` or `< 5.11.2`) confirmed.

---

## 💡 Remediation
1. **Update Craft CMS**: Upgrade immediately to **`4.18.9+`** (for v4 deployments) or **`5.11.2+`** (for v5 deployments) via `php craft update all` or Composer (`composer update craftcms/cms`).
2. **Minimize Banner Exposure**: Set `'sendPoweredByHeader' => false` in `config/general.php`.
