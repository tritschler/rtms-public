# Sonatype Nexus Repository 3 SAML/OIDC Account Bypass Audit (`CVE-2026-113373`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--113373-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **Sonatype Nexus Repository 3** instances (`3.86.0` to `3.97.1`) exposed to **CVE-2026-113373**.

---

## Overview
- **CVE:** `CVE-2026-113373` (CVSS 9.1 Critical)
- **Severity**: **Critical (CVSS 9.1)**
- **CWE**: CWE-287 / CWE-305 (Improper Authentication)
- **Affected Component:** Sonatype Nexus Repository 3 Pro versions `3.86.0` through `3.97.1` (`< 3.98.0`)
- **Patched Version:** `3.98.0+`
- **Target Ports:** `8081`, `80`, `443`, `8443`

---

## Vulnerability Summary
**Sonatype Nexus Repository 3 Pro (`3.86.0` prior to `3.98.0`)** does not verify the local account status when a user signs in via a configured SAML or OAuth2/OpenID Connect (OIDC) identity provider. A user whose local account was disabled or locked by a Nexus administrator can authenticate through the identity provider and obtain a new active session retaining the account's full roles and privileges.

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public HTTP `Server` header and UI status endpoints (`/service/rest/v1/status`, `/`) without attempting any authentication.

---

## Usage
```bash
# Audit standard Nexus Repository ports (8081, 80, 443, 8443)
python plugins/nexus_repository/nexus_cve_2026_113373_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/nexus_repository/nexus_cve_2026_113373_audit.py <target_ip> -p 8081 8443 --timeout 5.0
```

---

## Remediation
1. **Upgrade Nexus Repository:** Immediately update Sonatype Nexus Repository 3 to version **`3.98.0`** or later.
2. **Enforce IdP Deprovisioning:** Ensure revoked or suspended users are immediately disabled directly at the upstream SAML or OIDC Identity Provider in addition to local Nexus user management.
