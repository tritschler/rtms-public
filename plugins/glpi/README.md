# GLPI Two-Factor Authentication Bypass Audit (`CVE-2026-52848`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--52848-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **GLPI** instances (`11.0.0` to `11.0.7`) exposed to **CVE-2026-52848**.

---

## Overview
- **CVE:** `CVE-2026-52848` (CVSS 9.2 Critical)
- **Severity**: **Critical (CVSS 9.2)**
- **CWE**: CWE-287 / CWE-288 (Improper Authentication / Authentication Bypass)
- **Affected Component:** GLPI versions `11.0.0` through `11.0.7` (`< 11.0.8`)
- **Patched Version:** `11.0.8+`
- **Target Ports:** `80`, `443`, `8080`, `8443`

---

## Vulnerability Summary
In **GLPI versions `11.0.0` prior to `11.0.8`**, a flaw in the login workflow allows an unauthenticated user to supply a crafted URL to skip one-time-password (OTP) verification, effectively bypassing two-factor authentication (2FA).

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public GLPI web interface (`/`, `/front/login.php`, `/index.php`, `/apirest.php`) for GLPI signatures and disclosed version markers without attempting any authentication bypass.

---

## Usage
```bash
# Audit standard GLPI HTTP/HTTPS ports (80, 443, 8080, 8443)
python plugins/glpi/glpi_cve_2026_52848_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/glpi/glpi_cve_2026_52848_audit.py <target_ip> -p 80 443 --timeout 5.0
```

---

## Remediation
1. **Upgrade GLPI:** Immediately update GLPI to version **`11.0.8`** or later.
2. **Audit Authentication Logs:** Review GLPI security logs (`files/_log/security.log`) for anomalous login sessions where 2FA verification was skipped.
