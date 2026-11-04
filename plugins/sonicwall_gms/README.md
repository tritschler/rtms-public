# SonicWall GMS Unauthenticated Internal File Read Audit (`CVE-2026-109593`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--109593-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **SonicWall Global Management System (GMS)** instances (`<= 9.5.2`) exposed to **CVE-2026-109593**.

---

## Overview
- **CVE:** `CVE-2026-109593` (CVSS 9.1 Critical)
- **Severity**: **Critical (CVSS 9.1)**
- **CWE**: CWE-22 / CWE-200 (Arbitrary File Read / Sensitive Information Exposure)
- **Affected Component:** SonicWall Global Management System (GMS) versions `<= 9.5.2`
- **Patched Version:** `> 9.5.2` (`9.5.3+` / latest SonicWall security release)
- **Target Ports:** `80`, `443`, `8080`, `8443`

---

## Vulnerability Summary
An unauthenticated attacker with network access to **SonicWall Global Management System (GMS) `9.5.2` and earlier versions** can read internal GMS files, potentially exposing sensitive configuration files, credentials, and appliance management secrets.

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public web login portals (`/sgms/login`, `/appliance/login`, `/`) for SonicWall GMS signatures and disclosed version strings without attempting any file-read exploitation.

---

## Usage
```bash
# Audit standard SonicWall GMS HTTP/HTTPS ports (80, 443, 8080, 8443)
python plugins/sonicwall_gms/sonicwall_gms_cve_2026_109593_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/sonicwall_gms/sonicwall_gms_cve_2026_109593_audit.py <target_ip> -p 443 8443 --timeout 5.0
```

---

## Remediation
1. **Apply Official SonicWall Updates:** Immediately upgrade SonicWall Global Management System (GMS) to a patched version (`> 9.5.2`) or apply the official SonicWall security hotfix.
2. **Restrict Management Access:** Ensure the SonicWall GMS web management interfaces (`/sgms/`, `/appliance/`, ports `80`, `443`, `8080`, `8443`) are never exposed directly to the public Internet and are restricted to authorized administrative IP addresses or VPN subnets.
