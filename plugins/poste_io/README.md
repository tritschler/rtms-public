# Poste.io Mail Server DMARC Processing RCE Compliance Auditor (CVE-2026-127027)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--127027-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Poste.io Mail Server** (`< 2.5.22`) against a critical command injection vulnerability in DMARC report attachment unpacking (`CVSS 9.2`).

---

## 🔍 Advisory Overview

* **CVE-2026-127027** (`CVSS 9.2 Critical`): Unsafe shell unpacking of incoming DMARC report attachments in Poste.io prior to version `2.5.22`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Poste.io Mail Server (FREE / PRO)** | `< 2.5.22` (`<= 2.5.21`) | `>= 2.5.22` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/poste_io/poste_io_cve_2026_127027_audit.py mail.internal.corp -p 443 80 8443
```
