# PHP & PHP-FPM Multi-CVE Version Compliance Auditor (CVE-2026-129289)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--129289-orange.svg)]()

A passive, read-only version compliance tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **PHP & PHP-FPM** (`8.2.x < 8.2.36`, `8.3.x < 8.3.37`, `8.4.x < 8.4.28`, `8.5.x < 8.5.13`) against 7 critical memory corruption, session deserialization, and FastCGI request smuggling vulnerabilities (`CVSS 9.2`).

---

## 🔍 Advisory Overview

* **CVE-2026-129289** (`CVSS 9.2 Critical`): PHP-FPM request smuggling through an unread HTTP request body when backend FastCGI connections are reused.
* **CVE-2026-129496** (`CVSS 9.2 Critical`): Timezone cache use-after-free leading to worker crash or remote code execution.
* **CVE-2026-126714** (`CVSS 9.2 Critical`): Partially overwritten session files leading to object injection and remote code execution.
* **CVE-2026-115560** (`CVSS 9.2 Critical`): Session serializer mismatch leading to object injection and remote code execution.
* **CVE-2026-129481** (`CVSS 9.2 Critical`): Use-after-free after interrupted session shutdown.
* **CVE-2026-129474** (`CVSS 9.2 Critical`): Use-after-free in magic method backtraces leading to remote code execution.
* **CVE-2026-129182** (`CVSS 9.2 Critical`): Use-after-free via repopulation of `last_fatal_error_backtrace` global after shutdown.

---

## 📋 Affected Versions & Remediation Matrix

| Branch | Affected Versions | Patched Version |
|:---|:---:|:---:|
| **PHP 8.2.x** | `8.2.0` – `8.2.35` (`< 8.2.36`) | `>= 8.2.36` |
| **PHP 8.3.x** | `8.3.0` – `8.3.36` (`< 8.3.37`) | `>= 8.3.37` |
| **PHP 8.4.x** | `8.4.0` – `8.4.27` (`< 8.4.28`) | `>= 8.4.28` |
| **PHP 8.5.x** | `8.5.0` – `8.5.12` (`< 8.5.13`) | `>= 8.5.13` |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/php_fpm/php_fpm_cve_2026_129289_audit.py app.internal.corp -p 80 443 8080 8443
```
