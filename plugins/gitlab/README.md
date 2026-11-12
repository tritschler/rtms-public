# GitLab CE/EE Version Compliance Auditor (CVE-2026-110264 & CVE-2026-85706)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--110264-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **GitLab Community Edition (CE) & Enterprise Edition (EE)** instances against **CVE-2026-110264** (`CVSS 10.0`) and **CVE-2026-85706** (`CVSS 10.0`).

---

## 🔍 Advisory Overview

* **CVE-2026-110264** (`CVSS 10.0 Critical` — `CWE-190`): Unauthenticated remote code execution on GitLab CE/EE due to an integer overflow when compiling a specially crafted regular expression.
* **CVE-2026-85706** (`CVSS 10.0 Critical` — `CWE-22`): Unauthenticated arbitrary file read on the GitLab server due to improper path confinement.

---

## 📋 Affected Versions & Remediation Matrix

| GitLab Branch | Affected Versions | Patched Version |
|:---:|:---:|:---:|
| **19.5** | `19.5.0` | `>= 19.5.1` |
| **19.4** | `19.4.0` through `19.4.2` | `>= 19.4.3` |
| **19.3** | `19.3.0` through `19.3.5` | `>= 19.3.6` |
| **19.2** | `19.2.0` through `19.2.8` | `>= 19.2.9` |
| **19.1** | `19.1.0` through `19.1.8` | `>= 19.1.9` |
| **19.0** | `19.0.0` through `19.0.9` | `>= 19.0.10` |
| **7.0 – 18.11** | `< 18.11.13` | `>= 18.11.13` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/gitlab/gitlab_cve_2026_110264_audit.py gitlab.internal.corp -p 80 443 8080 8443
```
