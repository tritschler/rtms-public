# Jenkins Script Security Plugin Sandbox Bypass Auditor (CVE-2026-136835)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--136835-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Jenkins Script Security Plugin** (`<= 1436.v1082791135e4`) against a critical sandbox bypass vulnerability (`CVSS 9.9`).

---

## 🔍 Advisory Overview

* **CVE-2026-136835** (`CVSS 9.9 Critical`): Insufficient validation of `@Builder` annotations in **Jenkins Script Security Plugin** (`script-security`) `1436.v1082791135e4` and earlier allows users with permission to define and run sandboxed scripts (including Pipelines) to bypass the Groovy sandbox.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Jenkins Script Security Plugin (`script-security`)** | `<= 1436.v1082791135e4` | `> 1436.v1082791135e4` (`1437+`) |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/jenkins/jenkins_cve_2026_136835_audit.py jenkins.internal.corp -p 8080 8443 443
```
