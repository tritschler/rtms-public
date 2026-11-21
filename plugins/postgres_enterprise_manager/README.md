# Postgres Enterprise Manager (PEM) Multi-CVE Version Compliance Auditor (CVE-2026-132660)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.4_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--132660-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **EDB Postgres Enterprise Manager (PEM)** (`< 10.6.1`) against 3 critical backend database privilege escalation and agent isolation vulnerabilities (`CVSS 9.4`).

---

## 🔍 Advisory Overview

* **CVE-2026-132660** (`CVSS 9.4 Critical`): `SECURITY DEFINER` functions in the `pem` schema of the PEM backend PostgreSQL database are owned by a superuser without setting a fixed `search_path`.
* **CVE-2026-132659** (`CVSS 9.4 Critical`): Row-level security (RLS) policies on `pem.job` and `pem.jobstep` do not restrict a PEM agent to its own jobs.
* **CVE-2026-132658** (`CVSS 9.4 Critical`): The `pem_agent` role inherited by PEM agent logins is granted membership in `pg_read_server_files` and `pg_write_server_files` on the PEM backend database.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **EDB Postgres Enterprise Manager (PEM)** | `< 10.6.1` (`<= 10.6.0`) | `>= 10.6.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/postgres_enterprise_manager/postgres_enterprise_manager_cve_2026_132660_audit.py db-admin.internal.corp -p 8443 8444 443
```
