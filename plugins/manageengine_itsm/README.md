# Zoho ManageEngine ITSM, M365 Manager Plus & DDI Central Compliance Auditor (CVE-2026-12591 / CVE-2026-12507 / CVE-2026-19422)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--12591-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Zoho ManageEngine M365 Manager Plus**, **ServiceDesk Plus**, **AssetExplorer**, **SupportCenter Plus**, and **DDI Central** deployments against **CVE-2026-12591**, **CVE-2026-12507**, and **CVE-2026-19422** (`CVSS 9.1–9.9`).

---

## 🔍 Advisory Overview

* **CVE-2026-12591** (`CVSS 9.9 Critical`): Insufficient permission validation in the delegated administration interface of **ManageEngine M365 Manager Plus** (`< 4818`) allowing privilege escalation and remote code execution.
* **CVE-2026-12507** (`CVSS 9.1 Critical`): Authenticated remote code execution in the Reports module of **ServiceDesk Plus** (`< 15290`), **AssetExplorer** (`< 7860`), **ServiceDesk Plus MSP** (`< 15150`), and **SupportCenter Plus** (`< 15150`).
* **CVE-2026-19422** (`CVSS 9.1 Critical`): Authentication bypass in Windows DNS and DHCP agent synchronization APIs in **ManageEngine DDI Central** (`< 6301`).

---

## 📋 Affected Builds & Remediation Matrix

| ManageEngine Product | Target CVE | Affected Builds | Patched Build |
|:---|:---:|:---:|:---:|
| **M365 Manager Plus** | `CVE-2026-12591` | `< 4818` | `>= 4818` |
| **ServiceDesk Plus** | `CVE-2026-12507` | `< 15290` | `>= 15290` |
| **ServiceDesk Plus MSP** | `CVE-2026-12507` | `< 15150` | `>= 15150` |
| **SupportCenter Plus** | `CVE-2026-12507` | `< 15150` | `>= 15150` |
| **AssetExplorer** | `CVE-2026-12507` | `< 7860` | `>= 7860` |
| **DDI Central** | `CVE-2026-19422` | `< 6301` | `>= 6301` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/manageengine_itsm/manageengine_itsm_cve_2026_12591_audit.py servicedesk.internal.corp -p 8080 8443
```
