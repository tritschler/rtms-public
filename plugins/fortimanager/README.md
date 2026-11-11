# Fortinet FortiManager Version Compliance Auditor (CVE-2026-126261)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--126261-orange.svg)]()

A passive, read-only version and service exposure compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Fortinet FortiManager** appliances against **CVE-2026-126261**.

---

## 🔍 Advisory Overview

* **CVE-2026-126261** (`CVSS 9.8 Critical`): Improper authorization vulnerability in Fortinet FortiManager affecting the FortiGate-to-FortiManager (`FGFM`) management protocol.

---

## 📋 Affected Versions & Remediation Matrix

| FortiManager Branch | Affected Versions | Patched Version |
|:---:|:---:|:---:|
| **8.0** | `8.0.0` | `>= 8.0.1` |
| **7.6** | `7.6.0` through `7.6.7` | `>= 7.6.8` |
| **7.4** | `7.4.0` through `7.4.5` | `>= 7.4.6` |
| **7.2** | `7.2.0` through `7.2.8` | `>= 7.2.9` |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (uses Python standard library `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/fortimanager/fortimanager_cve_2026_126261_audit.py fmg.internal.corp -p 443 541 8443
```

### Exit Codes
* **`0`**: Host is compliant or no affected FortiManager service detected.
* **`1`**: Affected FortiManager version detected.

---

## 💡 Remediation
1. **Upgrade Firmware**: Update FortiManager to version `7.2.9+`, `7.4.6+`, `7.6.8+`, or `8.0.1+`.
2. **Restrict FGFM Port (`541/TCP`)**: Apply `local-in-policy` rules to allow FGFM connections only from authorized FortiGate IP addresses.
3. **Disable Unknown Devices**: Configure `set fgfm-deny-unknown enable` under `config system global`.
