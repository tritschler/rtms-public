# Apache OFBiz Screen Descriptor & Login Key Audit (`CVE-2026-83542` / `CVE-2026-82907`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--83542-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **Apache OFBiz** instances (`< 24.09.08`) exposed to **CVE-2026-83542** and **CVE-2026-82907**.

---

## Overview
- **CVE:** `CVE-2026-83542` / `CVE-2026-82907` (CVSS 9.8 Critical)
- **Severity:** **Critical (CVSS 9.8)**
- **CWE:** CWE-94 (Improper Control of Generation of Code) / CWE-294 (Authentication Bypass by Capture-replay)
- **Affected Component:** Apache OFBiz versions prior to `24.09.08` (`< 24.09.08`)
- **Patched Version:** `24.09.08+`
- **Target Ports:** `8443`, `8080`, `443`, `80`

---

## Vulnerability Summary
**Apache OFBiz prior to `24.09.08`** is affected by two critical vulnerabilities:
1. **CVE-2026-83542 (CVSS 9.8):** Improper control of code generation in the screen widget descriptor mechanism when overriding `mainDecoratorLocation` or accessing public portal routes.
2. **CVE-2026-82907 (CVSS 9.8):** Authentication bypass by capture-replay in `ExternalLoginKeysManager`, where `checkExternalLoginKey` accepts reusable keys across web applications without binding or expiration.

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public HTTP response headers (`OFBiz.Visitor` cookie, `Server` header) and UI version footers on `/webtools/control/main`, `/ordermgr/control/main`, and `/`.

---

## Usage
```bash
# Audit standard Apache OFBiz ports (8443, 8080, 443, 80)
python plugins/apache_ofbiz/apache_ofbiz_cve_2026_83542_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/apache_ofbiz/apache_ofbiz_cve_2026_83542_audit.py <target_ip> -p 8443 8080 --timeout 5.0
```

---

## Remediation
1. **Upgrade Apache OFBiz:** Immediately update Apache OFBiz to version **`24.09.08`** or later.
2. **Restrict Administrative Exposure:** Limit network access to `/webtools`, `/ordermgr`, and `/sfa` endpoints to trusted management networks or VPNs.
