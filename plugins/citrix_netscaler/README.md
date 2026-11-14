# Citrix NetScaler Console & ADC/Gateway Compliance Auditor (CVE-2026-120869 / CVE-2026-107412)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.5_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--120869_&_CVE--2026--107412-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Citrix NetScaler Console / ADC & Gateway** appliances against **CVE-2026-120869** (`CVSS 9.3`) and the November 2026 NetScaler ADC/Gateway security bulletin (`CVE-2026-107412`, `CVE-2026-107415`, `CVE-2026-107410`, `CVE-2026-107409`, `CVE-2026-107408`, `CVE-2026-107407`, `CVE-2026-120868`, `CVE-2026-120864`, `CVE-2026-111334` — `CVSS 9.3–9.5`).

---

## 🔍 Advisory Overview

* **CVE-2026-120869** (`CVSS 9.3 Critical` — `CWE-287`): Authentication bypass on the Citrix NetScaler Console appliance.
* **CVE-2026-107412** (`CVSS 9.5 Critical`): Multiple memory overflow vulnerabilities in Citrix NetScaler ADC and NetScaler Gateway.
* **CVE-2026-107415**, **CVE-2026-107410**, **CVE-2026-107409**, **CVE-2026-107408**, **CVE-2026-107407**, **CVE-2026-120868**, **CVE-2026-120864**, **CVE-2026-111334** (`CVSS 9.3 Critical`): Memory overflow and memory corruption flaws in Email OTP, NetScaler Push, DNS-over-HTTPS (DoH), SMPP traffic, Packet Processing, ICA Proxy, and Endpoint Analysis (EPA/EPAS).

---

## 📋 Affected Versions & Remediation Matrix

| NetScaler Branch | Affected ADC / Gateway Builds | Patched ADC / Gateway Build |
|:---:|:---:|:---:|
| **14.1** | `< 14.1-73.57` (Console `< 14.1-38.53`) | `>= 14.1-73.57` |
| **13.1** | `< 13.1-64.39` (Console `< 13.1-56.18`) | `>= 13.1-64.39` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/citrix_netscaler/citrix_netscaler_cve_2026_120869_audit.py netscaler.internal.corp -p 443 8443 9443
```
