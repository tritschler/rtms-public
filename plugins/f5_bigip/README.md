# F5 BIG-IP TMOS & APM Multi-CVE Version Compliance Auditor (CVE-2026-123637)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--123637-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **F5 BIG-IP** (`17.1.x < 17.1.3.6`, `17.5.x < 17.5.1.10`, `21.1.x < 21.1.0.2`) against 7 critical vulnerabilities (`CVSS 9.2–9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-123637** (`CVSS 9.3 Critical`): Traffic Management Microkernel (TMM) termination and potential Remote Code Execution when BIG-IP APM is provisioned with Client Information and Endpoint Security per-request policy agents.
* **CVE-2026-120722** (`CVSS 9.3 Critical`): TMM termination and potential RCE when an iRule using `DNS::scrape` is configured on a virtual server.
* **CVE-2026-121805** (`CVSS 9.3 Critical`): TMM termination and potential RCE when an iRule using `PEM::subscriber` is configured on a virtual server.
* **CVE-2026-116953** (`CVSS 9.3 Critical`): TMM termination and potential RCE when an iRule using `GENERICMESSAGE::route` is configured on a virtual server.
* **CVE-2026-120292** (`CVSS 9.3 Critical`): TMM termination and potential RCE when an HTTP profile and an iRule using `MR::message route` are configured.
* **CVE-2026-120285** (`CVSS 9.3 Critical`): TMM termination and potential RCE when an HTTP profile and an iRule using `PSC::ip_address` are configured.
* **CVE-2026-120718** (`CVSS 9.2 Critical`): BIG-IP iControl REST authentication tokens may fail to expire as expected.

---

## 📋 Affected Versions & Remediation Matrix

| Product Branch | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **F5 BIG-IP 21.1.x** | `21.1.0` – `21.1.0.1` (`< 21.1.0.2`) | `>= 21.1.0.2` |
| **F5 BIG-IP 17.5.x** | `17.5.0` – `17.5.1.9` (`< 17.5.1.10`) | `>= 17.5.1.10` |
| **F5 BIG-IP 17.1.x** | `17.1.0` – `17.1.3.5` (`< 17.1.3.6`) | `>= 17.1.3.6` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/f5_bigip/f5_bigip_cve_2026_123637_audit.py bigip.internal.corp -p 443 8443
```
