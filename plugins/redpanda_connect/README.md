# Redpanda Connect Version Compliance Auditor (CVE-2026-123270)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--123270-orange.svg)]()

A passive, read-only version compliance audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to verify **Redpanda Connect** deployments against **CVE-2026-123270** (Missing Authentication on HTTP Management API in versions `4.39` to `4.110`).

---

## 🔍 Advisory Overview

* **CVE ID**: `CVE-2026-123270`
* **Severity**: **Critical (CVSS v3.1: 9.8)**
* **CWE**: CWE-306 (Missing Authentication for Critical Function)
* **Affected Ecosystems**: Redpanda Connect versions `4.39.0` through `4.110.x` running in streams mode with the HTTP management interface exposed (default TCP port `4195`).

---

## 📋 Affected & Patched Versions

| Component | Affected Versions | Patched / Safe Release |
|:---|:---:|:---:|
| **Redpanda Connect** | `4.39.0` – `4.110.x` (`< 4.111.0`) | **`4.111.0+`** |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (standard Python library: `http.client`, `socket`, `ssl`, `re`).

### Run Passive Compliance Audit

```bash
python plugins/redpanda_connect/redpanda_connect_cve_2026_123270_audit.py stream-worker.internal.corp -p 4195 8080
```

### Exit Codes
* **`0`**: Host is compliant (`>= 4.111.0`) or no Redpanda Connect HTTP service detected.
* **`1`**: Affected Redpanda Connect version (`4.39` to `4.110`) confirmed.

---

## 💡 Remediation
1. **Upgrade to Redpanda Connect `4.111.0+`**: In version `4.111.0` and later, the HTTP management endpoint is disabled by default unless explicitly opted in.
2. **Restrict Management Port Access**: Ensure TCP port `4195` is bound only to `127.0.0.1` or protected by strict network segmentation and reverse-proxy authentication.
