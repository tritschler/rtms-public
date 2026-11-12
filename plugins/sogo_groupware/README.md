# Alinto SOGo Groupware 2FA & Account Recovery Auditor (CVE-2026-127131 & CVE-2026-127111)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--127131-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Alinto SOGo Groupware / Webmail** deployments (`< 5.12.13`) against **CVE-2026-127131** (`CVSS 9.1`) and **CVE-2026-127111** (`CVSS 9.1`).

---

## 🔍 Advisory Overview

* **CVE-2026-127131** (`CVSS 9.1 Critical` — `CWE-307`): Missing rate limiting in SOGo web login TOTP verification (`/SOGo/connect`) allowing attackers to brute-force 2FA codes without triggering account lockout.
* **CVE-2026-127111** (`CVSS 9.1 Critical` — `CWE-307`): Improper restriction of excessive authentication attempts in `passwordRecoveryCheck` allowing unauthenticated password reset via secret-question guessing.

---

## 📋 Affected Versions & Remediation Matrix

| SOGo Branch | Affected Versions | Patched Version |
|:---:|:---:|:---:|
| **5.x** | `< 5.12.13` | `>= 5.12.13` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/sogo_groupware/sogo_cve_2026_127131_audit.py webmail.internal.corp -p 80 443 20000
```
