# WordPress WP Photo Album Plus Code Injection Audit (CVE-2026-129048)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WP Photo Album Plus** (`wp-photo-album-plus`) installations against **CVE-2026-129048** (`CVSS 9.9`).

---

## 🔍 Advisory Overview

* **CVE-2026-129048** (`CVSS 9.9 Critical`): Improper Control of Generation of Code (Code Injection / Remote Code Inclusion) in WP Photo Album Plus (`<= 9.3.06.003`).

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **WP Photo Album Plus** | `<= 9.3.06.003` (`< 9.3.06.004`) | `>= 9.3.06.004` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_photo_album_plus/wp_photo_album_plus_cve_2026_129048_audit.py wp.example.com -p 80 443
```
