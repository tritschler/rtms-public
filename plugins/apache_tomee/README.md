# Apache TomEE & OpenEJB Version Compliance Audit (`CVE-2026-87756` & 8 Related CVEs)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Apache TomEE** and **OpenEJB** server installations (`< 10.3.0` and `11.0.0-M1`) against 9 critical authentication bypass, identity reuse, and remote EJB role enforcement vulnerabilities (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-87756** (`CVSS 9.8`): Missing administrative role check on internal system EJBs used for remote deployment and configuration.
* **CVE-2026-97880** (`CVSS 9.8`): Embedded OpenEJB HTTP server dispatches requests to HTTP Basic protected REST endpoints without verifying credentials.
* **CVE-2026-97888** (`CVSS 9.8`): Embedded HTTP server does not clear security identity on worker threads between requests.
* **CVE-2026-111240** (`CVSS 9.8`): JDBC JAAS login module accepts passwordless login for accounts whose stored password is `NULL`.
* **CVE-2026-111244** (`CVSS 9.8`): Incomplete enforcement of MicroProfile JWT role-based access control on JAX-RS resources.
* **CVE-2026-111245** (`CVSS 9.8`): WS-Security `UsernameToken` caller identity remains bound to standalone OpenEJB HTTP worker threads across requests.
* **CVE-2026-111250** (`CVSS 9.8`): Embedded OpenEJB HTTP server reports every request as authenticated for programmatic authentication checks.
* **CVE-2026-111256** (`CVSS 9.8`): Embedded OpenEJB HTTP server ignores configured authentication methods on JAX-WS and JAX-RS endpoints.
* **CVE-2026-111264** (`CVSS 9.8`): Generated security constraints for EJB JAX-WS endpoints protect only a subset of HTTP methods.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Apache TomEE / OpenEJB 10.x & earlier** | `< 10.3.0` (`1.x`, `4.x`, `7.x`–`9.x`, `10.0.0-M1`–`10.2.x`) | `>= 10.3.0` |
| **Apache TomEE 11.x** | `11.0.0-M1` (`< 11.0.0-M2`) | `>= 11.0.0-M2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/apache_tomee/apache_tomee_cve_2026_87756_audit.py tomee.example.com -p 8080 8443 4204
```
