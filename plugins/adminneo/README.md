# AdminNeo Database Manager Version Compliance Audit (`CVE-2026-130366` / `CVE-2026-130380`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **AdminNeo** database manager installations (`< 5.9.1`) against **CVE-2026-130366** and **CVE-2026-130380** (`CVSS 9.2`).

---

## 🔍 Advisory Overview

* **CVE-2026-130366** (`CVSS v4.0: 9.2 Critical`): Authentication bypass in the ClickHouse driver on passwordless accounts in AdminNeo before `5.9.1`.
* **CVE-2026-130380** (`CVSS v4.0: 9.2 Critical`): Authentication bypass in the `sqlsrv`-based MS SQL driver when an empty username is submitted in AdminNeo before `5.9.1`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **AdminNeo** | `< 5.9.1` | `>= 5.9.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/adminneo/adminneo_cve_2026_130366_audit.py dbadmin.example.com -p 80 443 8080
```
