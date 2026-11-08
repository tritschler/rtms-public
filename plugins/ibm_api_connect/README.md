# IBM API Connect Auth Bypass & RCE Audit (`CVE-2026-17301` / `CVE-2026-17408` / `CVE-2026-17360`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--17301-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **IBM API Connect** instances (`10.0.8.0`–`10.0.8.12` and `12.1.0.0`–`12.1.1.2`) exposed to **CVE-2026-17301**, **CVE-2026-17408**, **CVE-2026-17360**, **CVE-2026-17403**, and **CVE-2026-16720**.

---

## Overview
- **CVEs:** `CVE-2026-17301` (CVSS 9.8), `CVE-2026-17408` (CVSS 9.8), `CVE-2026-17360` (CVSS 9.8), `CVE-2026-17403` (CVSS 9.0), `CVE-2026-16720` (CVSS 9.8)
- **Severity:** **Critical (CVSS 9.8)**
- **CWE:** CWE-347 / CWE-78 / CWE-798 / CWE-287
- **Affected Component:** IBM API Connect `10.0.8.0` through `10.0.8.12` and `12.1.0.0` through `12.1.1.2`
- **Patched Versions:** `10.0.8.13+` and `12.1.1.3+`
- **Target Ports:** `443`, `8443`, `9443`, `3000`, `8080`, `80`

---

## Vulnerability Summary
1. **`CVE-2026-17301` (CVSS 9.8):** Improper verification of cryptographic signatures allows unauthenticated remote attackers to bypass authentication.
2. **`CVE-2026-17408` (CVSS 9.8):** Improper neutralization of special elements in OS commands allows remote attackers to execute arbitrary code on the underlying host.
3. **`CVE-2026-17360` / `CVE-2026-17403` (CVSS 9.8 / 9.0):** Hard-coded credentials allow remote attackers to gain full administrative control.
4. **`CVE-2026-16720` (CVSS 9.8):** Insufficient enforcement of directory service authentication allows remote attackers to obtain valid access tokens for other users.

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public IBM API Connect endpoints (`/api/cloud/settings`, `/api/cloud/version`, `/manager/`, `/admin/`, `/`) and response headers (`X-IBM-APIConnect-Version`, `Server`).

---

## Usage
```bash
# Audit standard IBM API Connect ports (443, 8443, 9443, 3000, 8080, 80)
python plugins/ibm_api_connect/ibm_api_connect_cve_2026_17301_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/ibm_api_connect/ibm_api_connect_cve_2026_17301_audit.py <target_ip> -p 443 8443 9443 --timeout 5.0
```

---

## Remediation
1. **Upgrade IBM API Connect:** Immediately update the `10.0.8.x` branch to **`10.0.8.13+`** and the `12.1.x` branch to **`12.1.1.3+`**.
2. **Network Segmentation:** Restrict external network access to Cloud Manager and Management APIs (`/api/cloud`, `/manager`) to trusted administrative networks or VPNs.
