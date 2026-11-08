# Keycloak Client Management JS Policy Upload RCE Audit (`CVE-2026-120984`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--120984-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **Keycloak / Red Hat Build of Keycloak** instances (`< 26.2.5`) exposed to **CVE-2026-120984**.

---

## Overview
- **CVE:** `CVE-2026-120984` (CVSS 9.1 Critical)
- **Severity:** **Critical (CVSS 9.1)**
- **CWE:** CWE-94 / CWE-284 (Code Injection / Improper Access Control)
- **Affected Component:** Keycloak / Red Hat Build of Keycloak `< 26.2.5` and Red Hat Single Sign-On 7.x
- **Patched Version:** `26.2.5+`
- **Target Ports:** `8080`, `8443`, `443`, `80`

---

## Vulnerability Summary
A flaw was found in the **Keycloak** server's client management component. When a client is created or imported with authorization services enabled, the system fails to properly clear an internal session attribute used during the setup process. This allows an authenticated attacker with client management permissions (`manage-clients`) to bypass security controls and upload a malicious JavaScript policy, which is then executed on the server when an authorization request is made, resulting in Remote Code Execution (RCE).

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public HTTP endpoints (`/admin/master/console/`, `/realms/master/.well-known/openid-configuration`, `/`) and static asset version paths (`/resources/<version>/...`).

---

## Usage
```bash
# Audit standard Keycloak ports (8080, 8443, 443, 80)
python plugins/keycloak_client_mgmt/keycloak_cve_2026_120984_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/keycloak_client_mgmt/keycloak_cve_2026_120984_audit.py <target_ip> -p 8080 8443 --timeout 5.0
```

---

## Remediation
1. **Upgrade Keycloak:** Immediately update Keycloak or Red Hat Build of Keycloak to version **`26.2.5`** or later.
2. **Restrict Script Upload & Client Management:** Keep script upload features disabled (`--features-disabled=scripts`) and strictly audit accounts assigned the `manage-clients` role.
