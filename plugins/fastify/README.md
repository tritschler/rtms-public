# Fastify Middleware (`@fastify/express` & `@fastify/middie`) Multi-CVE Auditor (CVE-2026-133120)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-5_Critical_CVEs-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Node.js Fastify middleware packages** (`@fastify/express < 4.0.10` and `@fastify/middie <= 9.3.7`) against five critical path-scoped middleware routing bypass vulnerabilities (`CVSS 9.1`).

---

## 🔍 Advisory Overview

* **CVE-2026-133120** (`CVSS 9.1 Critical`): Request path normalization mismatch between Fastify router and `@fastify/express` prior to `4.0.10`.
* **CVE-2026-129504** (`CVSS 9.1 Critical`): Prefix and mount path concatenation mismatch in `@fastify/express` `4.0.0` through `4.0.9`.
* **CVE-2026-133867** (`CVSS 9.1 Critical`): Regular-expression mount path mismatch under parameterized plugin prefixes in `@fastify/express` `4.0.7` through `4.0.9`.
* **CVE-2026-124626** (`CVSS 9.1 Critical`): Dynamic segment matcher discrepancy on empty path segments in `@fastify/express` `4.0.5` through `4.0.9`.
* **CVE-2026-133250** (`CVSS 9.1 Critical`): Path-scoped middleware routing mismatch in `@fastify/middie` through version `9.3.7`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version | Covered CVEs |
|:---|:---:|:---:|:---|
| **`@fastify/express`** | `< 4.0.10` (`<= 4.0.9`) | `>= 4.0.10` | `CVE-2026-133120`, `CVE-2026-129504`, `CVE-2026-133867`, `CVE-2026-124626` |
| **`@fastify/middie`** | `<= 9.3.7` (`< 9.3.8`) | `>= 9.3.8` | `CVE-2026-133250` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/fastify/fastify_cve_2026_133120_audit.py api.internal.corp -p 3000 8080 443
```
