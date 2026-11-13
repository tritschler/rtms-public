# Azul Payara Server & Payara Micro Compliance Auditor (CVE-2026-110003 & CVE-2026-90908)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--110003-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Azul Payara Server** and **Payara Micro** deployments against **CVE-2026-110003** and **CVE-2026-90908** (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-110003** (`CVSS 9.3 Critical`): A flaw in the administration REST interface of Azul Payara allows an unauthenticated remote attacker to bypass `secure-admin` remote-access restrictions on default domains with empty administrative credentials.
* **CVE-2026-90908** (`CVSS 9.3 Critical`): A flaw in `GenericAdminAuthenticator` of Azul Payara Server and Payara Micro allows an unauthenticated remote attacker to bypass JMX/RMI administrative access restrictions.

---

## 📋 Affected Versions & Remediation Matrix

| Payara Branch | Affected Versions | Patched Version |
|:---:|:---:|:---:|
| **Payara 7 Enterprise** | `7.0.0` – `< 7.6.0` | `>= 7.6.0` |
| **Payara 7 Community** | `7.2024.1` – `< 7.2026.11` | `>= 7.2026.11` |
| **Payara 6 Enterprise** | `6.0.0` – `< 6.44.0` | `>= 6.44.0` |
| **Payara 6 Community** | `6.2022.1` – `6.2025.11` | Migrate to `>= 7.2026.11` or Enterprise `>= 6.44.0` |
| **Payara 5 Enterprise** | `5.20.0` – `< 5.93.0` | `>= 5.93.0` |
| **Payara 4 Enterprise** | `< 4.1.2.191.61` | `>= 4.1.2.191.61` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/azul_payara/azul_payara_cve_2026_110003_audit.py payara.internal.corp -p 4848 8080 8181
```
