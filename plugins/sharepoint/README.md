# Microsoft SharePoint Server Version Compliance Auditor (CVE-2026-120002)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--120002-orange.svg)]()

A passive, read-only HTTP header version compliance audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify on-premises **Microsoft SharePoint Server** deployments against the November 2026 Patch Tuesday Critical SharePoint Advisories (`CVE-2026-120002`, `CVE-2026-80095`, and `CVE-2026-109454`).

---

## 🔍 Advisory Overview

* **CVE-2026-120002** (`CVSS 9.9 Critical`): Incorrect authorization in Microsoft Office SharePoint allowing privilege escalation over a network.
* **CVE-2026-80095** (`CVSS 9.0 Critical`): Cross-Site Scripting (XSS) privilege escalation in Microsoft Office SharePoint.
* **CVE-2026-109454** (`CVSS 9.0 Critical`): Cross-Site Scripting (Spoofing) in Microsoft Office SharePoint.

---

## 📋 Affected Editions & Minimum Patched Builds

| SharePoint Edition | Affected Builds (`MicrosoftSharePointTeamServices`) | Minimum Safe Build (Nov 2026 PU) |
|:---|:---:|:---:|
| **SharePoint Server Subscription Edition** | `< 16.0.18526.20650` | `>= 16.0.18526.20650` |
| **SharePoint Server 2019** | `< 16.0.10417.20075` | `>= 16.0.10417.20075` |
| **SharePoint Server 2016** | `< 16.0.5580.1000` | `>= 16.0.5580.1000` |
| **SharePoint Server 2013 / 2010 (`15.0` / `14.0`)** | All builds (End-of-Life) | Migrate to supported edition |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (uses Python standard library `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/sharepoint/sharepoint_cve_2026_120002_audit.py sharepoint.internal.corp -p 80 443 8080 8443
```

### Exit Codes
* **`0`**: Host is compliant or no affected SharePoint HTTP service detected.
* **`1`**: Unpatched SharePoint Server build detected.

---

## 💡 Remediation
1. **Apply November 2026 Cumulative Security Updates**: Install the latest security update package for your SharePoint Server edition.
2. **Run SharePoint Configuration Wizard**: Execute `psconfig.exe -cmd upgrade -inplace b2b -wait` across all servers in the SharePoint farm to complete schema and binary updates.
