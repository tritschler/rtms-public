# FrankenPHP Application Server Version Compliance Auditor (CVE-2026-128014 / CVE-2026-128023 / CVE-2026-128027)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Patched->=_1.13.2-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **FrankenPHP Application Server** instances against **CVE-2026-128014** (`CVSS 9.2`), **CVE-2026-128023** (`CVSS 9.1`), and **CVE-2026-128027** (`CVSS 9.3`).

---

## 🔍 Advisory Overview

* **CVE-2026-128014** (`CVSS 9.2 Critical`): FrankenPHP standalone static binaries `1.8.0` before `1.13.2` bundle the PHP brotli extension statically linked with Brotli 1.2.0, whose decoder contains an out-of-bounds write (`CVE-2026-111497`).
* **CVE-2026-128023** (`CVSS 9.1 Critical`): FrankenPHP before `1.13.0` contains an authentication bypass vulnerability regarding dot-form HTTP header names rewritten to underscores by PHP.
* **CVE-2026-128027** (`CVSS 9.3 Critical`): FrankenPHP Docker images before `1.1.11` did not propagate upstream security fixes under existing base tags.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Releases | Patched Release |
|:---:|:---:|:---:|
| **FrankenPHP Standalone / Server** | `< 1.13.2` (`1.8.0`–`1.13.1` for `CVE-2026-128014`, `< 1.13.0` for `CVE-2026-128023`) | `>= 1.13.2` |
| **FrankenPHP Docker Images** | `< 1.1.11` | `>= 1.13.2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/frankenphp/frankenphp_cve_2026_128014_audit.py app.internal.corp -p 80 443 8080 8443
```
