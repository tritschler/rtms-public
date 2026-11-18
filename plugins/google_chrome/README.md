# Google Chrome & Headless Chromium Sandbox Escape Auditor (CVE-2026-131088 / CVE-2026-126885)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.6_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--131088-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Google Chrome**, **Headless Chromium**, **Chrome DevTools Protocol (CDP)**, and **Selenium / WebDriver** endpoints against the November 2026 Chrome security bulletins (`< 158.0.8127.36` and `< 157.0.8103.78`, covering 18 critical CVEs).

---

## 🔍 Advisory Overview

### Chrome 158 Security Update (`< 158.0.8127.36`)
* **CVE-2026-131088** (`CVSS 9.6 Critical`): Improper input validation in `WebAppInstalls`.
* **CVE-2026-131077** (`CVSS 9.6 Critical`): Out-of-bounds write in `Tint`.
* **CVE-2026-131061** (`CVSS 9.6 Critical`): Buffer overflow in `Color`.
* **CVE-2026-131057** (`CVSS 9.6 Critical`): Out-of-bounds read in `ANGLE` on Android.
* **CVE-2026-131054** (`CVSS 9.6 Critical`): Out-of-bounds write in `ANGLE`.
* **CVE-2026-131031** (`CVSS 9.6 Critical`): Out-of-bounds write in `GPU`.
* **CVE-2026-131025** (`CVSS 9.6 Critical`): Out-of-bounds read in `ANGLE`.
* **CVE-2026-130994** (`CVSS 9.6 Critical`): Use-after-free in `WebGL`.
* **CVE-2026-130996** (`CVSS 9.6 Critical`): Out-of-bounds write in `ANGLE`.
* **CVE-2026-130971** (`CVSS 9.6 Critical`): Out-of-bounds write in `ANGLE`.
* **CVE-2026-130910** (`CVSS 9.6 Critical`): Protection mechanism failure in `ANGLE` on Android.

### Chrome 157 Security Update (`< 157.0.8103.78`)
* **CVE-2026-126885**, **CVE-2026-126846**, **CVE-2026-126872**, **CVE-2026-126842**, **CVE-2026-126909**, **CVE-2026-126912**, **CVE-2026-126859** (`CVSS 9.6 Critical`).

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Google Chrome / Headless Chromium** | `< 158.0.8127.36` | `>= 158.0.8127.36` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/google_chrome/google_chrome_cve_2026_126885_audit.py browserless.internal.corp -p 9222 4444 3000
```
