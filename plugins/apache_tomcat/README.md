# Apache Tomcat Multi-CVE Version Compliance Auditor (CVE-2026-133325)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--133325-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Apache Tomcat** (`11.0.x < 11.0.30`, `10.1.x < 10.1.63`, `9.0.x < 9.0.125`, and EOL `<= 8.5.x`) against 4 critical authentication, redirection, and cluster encryption vulnerabilities (`CVSS 9.1–9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-133325** (`CVSS 9.8 Critical`): Key exchange without entity authentication in Apache Tomcat clusters secured with TLS 1.3 and TLS-PSK (`11.0.28`–`11.0.29`, `10.1.62`, `9.0.124`).
* **CVE-2026-118028** (`CVSS 9.1 Critical`): Execution After Redirect (EAR) vulnerability in `RedirectValve` (`11.0.0-M18`–`11.0.27`, `10.1.20`–`10.1.61`, `9.0.87`–`9.0.123`).
* **CVE-2026-116561** (`CVSS 9.1 Critical`): Improper exception cleanup during Jakarta Authentication `secureResponse()` (`11.0.0-M1`–`11.0.27`, `10.1.0-M1`–`10.1.61`, `9.0.0.M1`–`9.0.123`, EOL `8.5.0`–`8.5.100`).
* **CVE-2026-95517** (`CVSS 9.1 Critical`): Encryption without integrity verification in `EncryptInterceptor` (`11.0.0-M1`–`11.0.27`, `10.1.0-M1`–`10.1.61`, `9.0.13`–`9.0.123`, EOL `8.5.38`–`8.5.100`, `7.0.100`–`7.0.109`).

---

## 📋 Affected Versions & Remediation Matrix

| Branch | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Apache Tomcat 11.0.x** | `11.0.0-M1` – `11.0.29` (`< 11.0.30`) | `>= 11.0.30` |
| **Apache Tomcat 10.1.x** | `10.1.0-M1` – `10.1.62` (`< 10.1.63`) | `>= 10.1.63` |
| **Apache Tomcat 9.0.x** | `9.0.0.M1` – `9.0.124` (`< 9.0.125`) | `>= 9.0.125` |
| **Apache Tomcat 7.0.x / 8.5.x (EOL)** | `7.0.100` – `7.0.109`, `8.5.0` – `8.5.100` | Upgrade to `9.0.125+` / `10.1.63+` / `11.0.30+` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/apache_tomcat/apache_tomcat_cve_2026_133325_audit.py app.internal.corp -p 8080 8443 80 443
```
