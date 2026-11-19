# NGINX Open Source & NGINX Plus Multi-CVE Version Compliance Auditor (CVE-2026-121810)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--121810-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **NGINX Open Source** (`< 1.30.7`, `1.31.0`–`1.31.8`) and **NGINX Plus** against 5 critical vulnerabilities (`CVSS 9.2`).

---

## 🔍 Advisory Overview

* **CVE-2026-121810** (`CVSS 9.2 Critical`): Use-after-free vulnerability in NGINX worker processes when HTTP/3 is enabled.
* **CVE-2026-123007** (`CVSS 9.2 Critical`): Heap buffer overflow in NGINX HTTP/2 flow control window handling.
* **CVE-2026-113425** (`CVSS 9.2 Critical`): Use-after-free vulnerability in NGINX worker processes when configured as a mail proxy.
* **CVE-2026-123634** (`CVSS 9.2 Critical`): Use-after-free vulnerability in NGINX proxy configurations using variable server names with SSI or mirror subrequests.
* **CVE-2026-123633** (`CVSS 9.2 Critical`): Use-after-free vulnerability in NGINX HTTP/2 client connection proxying under low `worker_connections`.

---

## 📋 Affected Versions & Remediation Matrix

| Product | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **NGINX Open Source (Stable)** | `0.5.33` – `1.30.6` (`< 1.30.7`) | `>= 1.30.7` |
| **NGINX Open Source (Mainline)** | `1.31.0` – `1.31.8` (`< 1.31.9`) | `>= 1.31.9` |
| **NGINX Plus** | `37.0.0` – `< 37.0.8.1`, `37.1.0` – `< 37.3.0.1` | `>= 37.0.8.1` / `>= 37.3.0.1` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/nginx/nginx_cve_2026_121810_audit.py web.internal.corp -p 80 443 8080 8443
```
