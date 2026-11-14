# WordPress Easy DragDrop File Uploader Arbitrary File Deletion Audit (CVE-2026-124822)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **WordPress Easy DragDrop File Uploader** installations against **CVE-2026-124822** (`CVSS 10.0`).

---

## 🔍 Advisory Overview

* **CVE-2026-124822** (`CVSS 10.0 Critical`): Unvalidated path handling in Easy DragDrop File Uploader before 1.1.10 allowing arbitrary file deletion.

---

## 📋 Affected Versions & Remediation Matrix

| WordPress Plugin | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Easy DragDrop File Uploader** | `< 1.1.10 (<= 1.1.9)` | `>= 1.1.10` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/wordpress/wp_easy_dragdrop_uploader/wp_easy_dragdrop_uploader_cve_2026_124822_audit.py wp.example.com -p 80 443
```
