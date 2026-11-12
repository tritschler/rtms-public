# Fortinet FortiOS Version Compliance Auditor (CVE-2026-126259)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--126259-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Fortinet FortiOS (FortiGate)** appliances against **CVE-2026-126259**, **CVE-2026-126254**, and **CVE-2026-126253**.

---

## 🔍 Advisory Overview

* **CVE-2026-126259** (`CVSS 9.8 Critical`): Missing authentication for critical function in FortiOS HA FGSP and autoscale configuration synchronization.
* **CVE-2026-126254** (`CVSS 9.6 Critical`): Numeric truncation error in FortiOS iBGP attribute handling.
* **CVE-2026-126253** (`CVSS 9.3 Critical`): Authentication bypass in FortiOS OSPF LSA handling.

---

## 📋 Affected Versions & Remediation Matrix

| FortiOS Branch | Affected Versions | Patched Version |
|:---:|:---:|:---:|
| **8.0** | `8.0.0` through `8.0.1` | `>= 8.0.2` |
| **7.6** | `7.6.0` through `7.6.7` | `>= 7.6.8` |
| **7.4** | `7.4.0` through `7.4.12` | `>= 7.4.13` |
| **7.2** | `7.2.0` through `7.2.13` | `>= 7.2.14` |
| **7.0** | `7.0.0` through `7.0.19` | `>= 7.0.20` |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (uses Python standard library `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/fortios/fortios_cve_2026_126259_audit.py fgt.internal.corp -p 443 8443 10443
```

### Exit Codes
* **`0`**: Host is compliant or no affected FortiOS service detected.
* **`1`**: Affected FortiOS version detected.

---

## 💡 Remediation
1. **Upgrade Firmware**: Update FortiOS to version `7.0.20+`, `7.2.14+`, `7.4.13+`, `7.6.8+`, or `8.0.2+`.
2. **Restrict Management & Routing Interfaces**: Apply `local-in-policy` rules and `trustedhost` restrictions to limit access to HA, BGP, OSPF, and management interfaces.
