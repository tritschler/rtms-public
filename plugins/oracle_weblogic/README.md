# Oracle WebLogic Server Multi-CVE Version Compliance Auditor (CVE-2026-91569)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--91569-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Oracle WebLogic Server** (`12.2.1.4.0`, `14.1.1.0.0`, `14.1.2.0.0`, `15.1.1.0.0`) against 7 critical vulnerabilities in the November 2026 Oracle Critical Patch Update.

---

## 🔍 Advisory Overview

* **CVE-2026-91569** (`CVSS 10.0 Critical`): Unauthenticated HTTP takeover vulnerability in WebLogic Server (`TopLink Integration`).
* **CVE-2026-91570** (`CVSS 9.8 Critical`): Unauthenticated HTTP takeover vulnerability in WebLogic Server (`TopLink Integration`).
* **CVE-2026-91583** (`CVSS 9.8 Critical`): Unauthenticated HTTP takeover vulnerability in WebLogic Server (`TopLink Integration`).
* **CVE-2026-91585** (`CVSS 9.8 Critical`): Unauthenticated TCP takeover vulnerability in WebLogic Server (`TopLink Integration`).
* **CVE-2026-91470** (`CVSS 9.8 Critical`): Unauthenticated T3 / IIOP takeover vulnerability in WebLogic Server (`Core`).
* **CVE-2026-91456** (`CVSS 9.8 Critical`): Unauthenticated SOAP takeover vulnerability in WebLogic Server (`Core`).
* **CVE-2026-91469** (`CVSS 9.4 Critical`): Unauthenticated HTTP data modification & DoS vulnerability in WebLogic Server (`Core`).

---

## 📋 Affected Versions & Remediation Matrix

| Product | Affected Versions | Remediation |
|:---|:---:|:---:|
| **Oracle WebLogic Server** | `12.2.1.4.0`, `14.1.1.0.0`, `14.1.2.0.0`, `15.1.1.0.0` | Apply November 2026 Oracle CPU (`PSU >= 261117`) |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/oracle_weblogic/oracle_weblogic_cve_2026_91569_audit.py wls.internal.corp -p 7001 7002 8443
```
