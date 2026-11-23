# Cribl Stream Version Compliance Auditor (CVE-2026-115899)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--115899-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Cribl Stream** deployments (`<= 4.20.4`) against **CVE-2026-115899** (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-115899** (`CVSS 9.3 Critical`): Code execution vulnerability when a Cribl Stream REST Collector configured with response-based pagination processes crafted upstream pagination metadata.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Cribl Stream** | `<= 4.20.4` (`< 4.20.5`) | `>= 4.20.5` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/cribl_stream/cribl_stream_cve_2026_115899_audit.py cribl.internal.corp -p 9000 443
```
