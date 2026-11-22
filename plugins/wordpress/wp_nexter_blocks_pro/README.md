# WordPress Nexter Blocks Pro Privilege Escalation Auditor (CVE-2026-125294)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--125294-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Nexter Blocks Pro** (`<= 5.0.10`) against a critical privilege escalation vulnerability (`CVSS 9.8`).

---

## 🔍 Advisory Overview

* **CVE-2026-125294** (`CVSS 9.8 Critical`): Privilege escalation via insufficient user metadata key filtering in `Nexter Blocks Pro` through version `5.0.10`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Nexter Blocks Pro (`the-plus-addons-for-block-editor-pro` / `nexter-blocks-pro`)** | `<= 5.0.10` (`< 5.0.11`) | `>= 5.0.11` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_nexter_blocks_pro/wp_nexter_blocks_pro_cve_2026_125294_audit.py wp.internal.corp -p 80 443
```
