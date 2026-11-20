# Splunk Enterprise & SOAR Multi-CVE Version Compliance Auditor (CVE-2026-76536)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--76536-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Splunk Enterprise**, **Splunk SOAR**, and **Splunk Enterprise Security** against 5 critical vulnerabilities (`CVSS 9.1`–`9.9`).

---

## 🔍 Advisory Overview

* **CVE-2026-76536** (`CVSS 9.4 Critical`): Unauthenticated cluster configuration exposure and modification via empty clustering shared secret on standalone Splunk Enterprise instances.
* **CVE-2026-76535** (`CVSS 9.1 Critical`): Unauthenticated arbitrary Search Processing Language (SPL) query execution through RapidDiag task collection in Splunk Enterprise.
* **CVE-2026-131253** (`CVSS 9.9 Critical`): Arbitrary code execution via the App Wizard in Splunk SOAR (`< 8.8.0`).
* **CVE-2026-131287** (`CVSS 9.6 Critical`): Arbitrary playbook code execution via cross-repository reference reuse in Splunk SOAR (`< 8.8.0`).
* **CVE-2026-131202** (`CVSS 9.1 Critical`): Arbitrary code execution combining lookup file upload and Configuration Checker in Splunk Enterprise Security (`< 8.7.0`).

---

## 📋 Affected Versions & Remediation Matrix

| Product | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Splunk Enterprise (9.4.x)** | `< 9.4.17` | `>= 9.4.17` |
| **Splunk Enterprise (10.0.x)** | `10.0.0` – `10.0.11` (`< 10.0.12`) | `>= 10.0.12` |
| **Splunk Enterprise (10.2.x)** | `10.2.0` – `10.2.8` (`< 10.2.9`) | `>= 10.2.9` |
| **Splunk Enterprise (10.4.x)** | `10.4.0` – `10.4.4` (`< 10.4.5`) | `>= 10.4.5` |
| **Splunk Enterprise (10.6.x)** | `10.6.0` (`< 10.6.1`) | `>= 10.6.1` |
| **Splunk SOAR** | `< 8.8.0` | `>= 8.8.0` |
| **Splunk Enterprise Security** | `< 8.7.0` | `>= 8.7.0` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/splunk_enterprise/splunk_enterprise_cve_2026_76536_audit.py splunk.internal.corp -p 8000 8089 443
```
