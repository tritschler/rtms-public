# Google Chrome & Headless Chromium Sandbox Escape Auditor (CVE-2026-126885)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.6_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--126885-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Google Chrome**, **Headless Chromium**, **Chrome DevTools Protocol (CDP)**, and **Selenium / WebDriver** endpoints against the November 2026 Chrome security bulletin (`< 157.0.8103.78`).

---

## 🔍 Advisory Overview

* **CVE-2026-126885** (`CVSS 9.6 Critical`): Use-after-free in `ServiceWorker` in Google Chrome prior to `157.0.8103.78`.
* **CVE-2026-126846** (`CVSS 9.6 Critical`): Use-after-free in `Skia` in Google Chrome prior to `157.0.8103.78`.
* **CVE-2026-126872** (`CVSS 9.6 Critical`): Incorrect authorization in `FileSystem` in Google Chrome prior to `157.0.8103.78`.
* **CVE-2026-126842** (`CVSS 9.6 Critical`): Use-after-free in `ANGLE` in Google Chrome prior to `157.0.8103.78`.
* **CVE-2026-126909** (`CVSS 9.6 Critical`): Use-after-free in `Passwords` in Google Chrome prior to `157.0.8103.78`.
* **CVE-2026-126912** (`CVSS 9.6 Critical`): Buffer overflow in `Skia` in Google Chrome prior to `157.0.8103.78`.
* **CVE-2026-126859** (`CVSS 9.6 Critical`): Link following in `FileSystem` in Google Chrome prior to `157.0.8103.78`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Google Chrome / Headless Chromium** | `< 157.0.8103.78` | `>= 157.0.8103.78` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/google_chrome/google_chrome_cve_2026_126885_audit.py browserless.internal.corp -p 9222 4444 3000
```
