# WordPress miniOrange OTP Verification Auth Bypass Auditor (CVE-2026-129073)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--129073-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress miniOrange OTP Verification** (`<= 5.6.1`) against a critical authentication bypass vulnerability (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-129073** (`CVSS 9.8 Critical`): Authentication bypass using an alternate path or channel in `miniorange-otp-verification` through version `5.6.1`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **miniOrange OTP Verification (`miniorange-otp-verification`)** | `<= 5.6.1` (`< 5.6.2`) | `>= 5.6.2` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_miniorange_otp_verification/wp_miniorange_otp_verification_cve_2026_129073_audit.py wp.internal.corp -p 80 443
```
