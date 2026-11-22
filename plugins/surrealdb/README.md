# SurrealDB Embedded JS Capability Bypass Compliance Auditor (CVE-2026-134292)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--134292-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **SurrealDB** (`>= 1.0.0, < 4.0.0`) against a critical capability check bypass vulnerability in its embedded JavaScript scripting engine (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-134292** (`CVSS 9.3 Critical`): Function capability check bypass in the embedded JavaScript scripting bridge (`surrealdb.functions`) in SurrealDB `1.0.0` before `4.0.0`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **SurrealDB** | `>= 1.0.0, < 4.0.0` (`<= 3.x`) | `>= 4.0.0` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/surrealdb/surrealdb_cve_2026_134292_audit.py db.internal.corp -p 8000 8080 443
```
