# Oracle MySQL Server & MySQL Cluster Version Compliance Auditor (CVE-2026-114952)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--114952-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Oracle MySQL Server** and **MySQL Cluster (NDB)** deployments against **CVE-2026-114952** (`CVSS 9.1 Critical`).

---

## 🔍 Advisory Overview

* **CVE-2026-114952** (`CVSS 9.1 Critical`): Vulnerability in the MySQL Server and MySQL Cluster product of Oracle MySQL (component: Client programs) allowing unauthenticated network compromise of critical data confidentiality and integrity.

---

## 📋 Affected Versions & Remediation Matrix

| Product | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Oracle MySQL Server 8.4 LTS** | `8.4.0` – `8.4.13` | `>= 8.4.14` |
| **Oracle MySQL Server 9.7** | `9.7.0` – `9.7.4` | `>= 9.7.5` |
| **Oracle MySQL Server 26.10** | `26.10` (`26.10.0`) | `>= 26.10.1` |
| **Oracle MySQL Cluster (NDB) 8.0** | `8.0.0` – `8.0.50` | `>= 8.0.51` |
| **Oracle MySQL Cluster (NDB) 8.4 / 9.7 / 26.10** | `8.4.0`–`8.4.13`, `9.7.0`–`9.7.4`, `26.10` | `>= 8.4.14` / `>= 9.7.5` / `>= 26.10.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/mysql/mysql_cve_2026_114952_audit.py db.internal.corp -p 3306 33060
```
