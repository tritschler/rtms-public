# Arize AI Phoenix Version Compliance Audit (`CVE-2026-53998`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Arize AI Phoenix** installations (`>= 13.0.0, < 15.7.0`) against **CVE-2026-53998** (`CVSS 10.0`).

---

## 🔍 Advisory Overview

* **CVE-2026-53998** (`CVSS v3.1: 10.0 Critical`): Attribute traversal in `FStringTemplateFormatter` via the `applyChatTemplate` GraphQL query in Arize AI Phoenix from `13.0.0` before `15.7.0`.

---

## 📋 Affected Versions & Remediation Matrix

| Component | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **Arize AI Phoenix** | `>= 13.0.0, < 15.7.0` | `>= 15.7.0` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/arize_phoenix/arize_phoenix_cve_2026_53998_audit.py phoenix.example.com -p 6006 80 443
```
