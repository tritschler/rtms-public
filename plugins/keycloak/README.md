# Keycloak SAML HTTP-Redirect Signature Verification Audit (`CVE-2026-117691`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--117691-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **Keycloak / Red Hat Build of Keycloak** instances (`< 26.2.0`) exposed to **CVE-2026-117691**.

---

## Overview
- **CVE:** `CVE-2026-117691` (CVSS 9.1 Critical)
- **Severity:** **Critical (CVSS 9.1)**
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Affected Component:** Keycloak / Red Hat Build of Keycloak `< 26.2.0` and Red Hat Single Sign-On 7.x
- **Patched Version:** `26.2.0+`
- **Target Ports:** `8080`, `8443`, `443`, `80`

---

## Vulnerability Summary
A flaw in the SAML HTTP-Redirect binding implementation of **Keycloak** causes the server to process percent-encoded parameter names while the signature verification logic only inspects literal parameter names. This discrepancy can allow an unverified SAML message to be accepted on SAML HTTP-Redirect endpoints, resulting in account takeover of federated users.

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public HTTP endpoints (`/admin/master/console/`, `/realms/master/.well-known/openid-configuration`, `/`) and static asset version paths (`/resources/<version>/...`).

---

## Usage
```bash
# Audit standard Keycloak ports (8080, 8443, 443, 80)
python plugins/keycloak/keycloak_cve_2026_117691_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/keycloak/keycloak_cve_2026_117691_audit.py <target_ip> -p 8080 8443 --timeout 5.0
```

---

## Remediation
1. **Upgrade Keycloak:** Immediately update Keycloak or Red Hat Build of Keycloak to version **`26.2.0`** or later.
2. **Enforce Binding Hygiene:** Prefer SAML HTTP-POST binding where applicable or block requests containing percent-encoded SAML parameter names (`%53AMLResponse`, `%53AMLRequest`) at the edge WAF / reverse proxy.
