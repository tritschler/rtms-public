# NoMachine nxwebrunner Web Service Audit (`CVE-2026-114549`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.0-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--114549-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **NoMachine** web service (`nxwebrunner` `<= 9.7.3`) instances exposed to **CVE-2026-114549**.

---

## Overview
- **CVE:** `CVE-2026-114549` (CVSS 9.8 Critical)
- **Severity**: **Critical (CVSS 9.8)**
- **CWE**: CWE-122 (Buffer Copy without Checking Size of Input)
- **Affected Component:** NoMachine (`nxwebrunner` web service) versions `<= 9.7.3`
- **Patched Version:** `> 9.7.3` (`9.7.4+`)
- **Target Ports:** `4443`, `4080`, `443`, `8443`

---

## Vulnerability Summary
A boundary validation vulnerability exists within the **NoMachine `nxwebrunner` web service** (listening on TCP port `4443` by default) in versions `9.7.3` and earlier.

This plugin performs a **strictly non-intrusive, read-only check** by sending a standard HTTP/HTTPS `GET` request to `/` and `/nxwebplayer` to identify NoMachine web service signatures and extract the version string without sending any malformed payload.

---

## Usage
```bash
# Audit standard NoMachine web ports (4443, 4080, 443, 8443)
python plugins/nomachine/nomachine_cve_2026_114549_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/nomachine/nomachine_cve_2026_114549_audit.py <target_ip> -p 4443 8443 --timeout 5.0
```

---

## Remediation
1. **Update NoMachine:** Immediately upgrade NoMachine to a patched release (`> 9.7.3`).
2. **Restrict Web Service Exposure:** If browser-based remote desktop access (`nxwebrunner` / `nxhtd`) is not required, disable the web service or restrict access to TCP port `4443` (and `4080`) to authorized management networks.
