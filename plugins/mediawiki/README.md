# MediaWiki & Extensions Multi-CVE Version Compliance Auditor (CVE-2026-132726 / CVE-2026-132694 / CVE-2026-132697 / CVE-2026-132669)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--132726-orange.svg)]()

A passive, read-only version compliance audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **MediaWiki** deployments against the November 2026 Wikimedia Foundation security advisories (**CVE-2026-132669**, **CVE-2026-132726**, **CVE-2026-132694**, and **CVE-2026-132697**).

---

## 🔍 Advisory Overview

* **CVE-2026-132669** (`CVSS v4.0: 9.3 Critical`): Improper access control in MediaWiki `EditAccount` Extension.
* **CVE-2026-132726** (`CVSS v4.0: 9.2 Critical`): Deserialization of untrusted data in MediaWiki `Echo` Extension (`1.43.0–<1.43.12`, `1.45.0–<1.45.7`, `1.46.0–<1.46.3`, `1.47.0`).
* **CVE-2026-132694** (`CVSS v4.0: 9.1 Critical`): Authentication validation flaw in MediaWiki `OATHAuth` Extension (`1.46.0–<1.46.3`, `1.47.0`).
* **CVE-2026-132697** (`CVSS v4.0: 9.1 Critical`): Missing authorization in MediaWiki `EmailAuth` Extension (`1.43`, `1.45`, `1.46`, `1.47`).

---

## 📋 Affected & Patched Versions

| Component | Affected Versions | Patched / Safe Release |
|:---|:---:|:---:|
| **MediaWiki 1.43 LTS** | `1.43.0` – `1.43.11` (`< 1.43.12`) | **`1.43.12+`** |
| **MediaWiki 1.45.x** | `1.45.0` – `1.45.6` (`< 1.45.7`) | **`1.45.7+`** |
| **MediaWiki 1.46.x** | `1.46.0` – `1.46.2` (`< 1.46.3`) | **`1.46.3+`** |
| **MediaWiki 1.47.x** | `1.47.0` (`< 1.47.1`) | **`1.47.1+`** |

---

## 🚀 Usage (Standalone CLI)

```bash
python plugins/mediawiki/mediawiki_cve_2026_132726_audit.py wiki.example.com -p 80 443 8080
```
