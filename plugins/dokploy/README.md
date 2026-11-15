# Dokploy PaaS Version Compliance Auditor (CVE-2026-129433)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.4_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Patched->=_0.31.1-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Dokploy PaaS** instances against **CVE-2026-129433** (`CVSS 9.4`).

---

## 🔍 Advisory Overview

* **CVE-2026-129433** (`CVSS 9.4 Critical`): Dokploy before `0.31.1` contains an OS command injection vulnerability in `getComposeContainerCommand()` via the `serviceName` parameter.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Releases | Patched Release |
|:---:|:---:|:---:|
| **Dokploy Server / PaaS** | `< 0.31.1` (`<= 0.31.0`) | `>= 0.31.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/dokploy/dokploy_cve_2026_129433_audit.py dokploy.internal.corp -p 80 443 3000 8080 8443
```
