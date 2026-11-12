# Citrix NetScaler Console Auth Bypass Auditor (CVE-2026-120869)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--120869-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Citrix NetScaler Console / ADC Gateway** appliances against **CVE-2026-120869** (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-120869** (`CVSS 9.3 Critical` — `CWE-287`): An unauthenticated attacker can bypass authentication controls to access restricted resources on the Citrix NetScaler Console appliance.

---

## 📋 Affected Versions & Remediation Matrix

| NetScaler Console Branch | Affected Builds | Patched Build |
|:---:|:---:|:---:|
| **14.1** | `< 14.1-38.53` | `>= 14.1-38.53` |
| **13.1** | `< 13.1-56.18` | `>= 13.1-56.18` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/citrix_netscaler/citrix_netscaler_cve_2026_120869_audit.py netscaler.internal.corp -p 443 8443 9443
```
