# Red Hat Quay Version Compliance Auditor (CVE-2026-110697 / CVE-2026-123710)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.9_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--110697-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Red Hat Quay / Project Quay** container registries against **CVE-2026-110697** and **CVE-2026-123710**.

---

## 🔍 Advisory Overview

* **CVE-2026-110697** (`CVSS 9.9 Critical`): Unescaped SQL LIKE wildcard metacharacters in Quay robot account listing allowing cross-tenant robot credential disclosure.
* **CVE-2026-123710** (`CVSS 9.8 Critical`): Missing restriction on the service key rotation endpoint allowing unauthenticated signing key registration.

---

## 📋 Affected Versions & Remediation Matrix

| Red Hat Quay Branch | Affected Versions | Patched Version |
|:---:|:---:|:---:|
| **3.18** | `< 3.18.2` | `>= 3.18.2` |
| **3.17** | `< 3.17.3` | `>= 3.17.3` |
| **3.16** | `< 3.16.4` | `>= 3.16.4` |
| **3.15** | `< 3.15.5` | `>= 3.15.5` |
| **3.14** | `< 3.14.6` | `>= 3.14.6` |
| **3.13** | `< 3.13.8` | `>= 3.13.8` |
| **3.12** | `< 3.12.11` | `>= 3.12.11` |
| **< 3.12** | End-of-Support | Upgrade to supported branch |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (uses Python standard library `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/redhat_quay/redhat_quay_cve_2026_110697_audit.py quay.internal.corp -p 443 8443 8080
```

### Exit Codes
* **`0`**: Host is compliant or no affected Red Hat Quay service detected.
* **`1`**: Affected Red Hat Quay version detected.

---

## 💡 Remediation
1. **Upgrade Registry**: Update Red Hat Quay to version `3.12.11+`, `3.13.8+`, `3.14.6+`, `3.15.5+`, `3.16.4+`, `3.17.3+`, or `3.18.2+`.
2. **Audit Service Keys & Robot Accounts**: Review approved service signing keys and rotate robot account credentials across namespaces.
