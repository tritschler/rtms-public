# VMware vCenter Server Directory Service Auth Bypass Auditor (CVE-2026-123890)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--123890-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **VMware vCenter Server** (`9.1.x < 9.1.1.0200`, `9.0.x < 9.0.2.0200`, `8.0 < 8.0 U3m`, `5.x < 5.2.5`) against a critical authentication bypass vulnerability in the VMware Directory Service (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-123890** (`CVSS 9.8 Critical`): Authentication bypass vulnerability in the VMware Directory Service (`vmdir`) in VMware vCenter Server (`KB463116`).

---

## 📋 Affected Versions & Remediation Matrix

| Product Branch | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **VMware vCenter Server 9.1.x** | `< 9.1.1.0200` | `>= 9.1.1.0200` |
| **VMware vCenter Server 9.0.x** | `< 9.0.2.0200` | `>= 9.0.2.0200` |
| **VMware vCenter Server 8.0.x** | `< 8.0 U3m` (`< 8.0.3.01300`) | `>= 8.0 U3m` |
| **VMware vCenter Server 5.x** | `< 5.2.5` | `>= 5.2.5` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/vmware_vcenter/vmware_vcenter_cve_2026_123890_audit.py vcenter.internal.corp -p 443 5480
```
