# WordPress Simple Shopping Cart Object Injection Auditor (CVE-2026-131782)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--131782-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Simple Shopping Cart** (`<= 5.3.3`) against a critical deserialization of untrusted data / PHP Object Injection vulnerability (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-131782** (`CVSS 9.8 Critical`): Deserialization of untrusted data allowing PHP Object Injection in `Simple Shopping Cart` (`wordpress-simple-paypal-shopping-cart`) through version `5.3.3`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Simple Shopping Cart (`wordpress-simple-paypal-shopping-cart`)** | `<= 5.3.3` (`< 5.3.4`) | `>= 5.3.4` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_simple_shopping_cart/wp_simple_shopping_cart_cve_2026_131782_audit.py wp.internal.corp -p 80 443
```
