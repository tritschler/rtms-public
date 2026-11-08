# OpenAM Live Session Token Disclosure & Auth Bypass Audit (`CVE-2026-123551` / `CVE-2026-123550` / `CVE-2026-123549`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v4.0-10.0_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--123551-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **OpenAM** identity servers (`< 16.1.4`) exposed to **CVE-2026-123551**, **CVE-2026-123550**, and **CVE-2026-123549**.

---

## Overview
- **CVEs:** `CVE-2026-123551` (CVSS 10.0 Critical), `CVE-2026-123550` (CVSS 9.3 Critical), `CVE-2026-123549` (CVSS 9.3 Critical)
- **Severity:** **Critical (CVSS 10.0)**
- **CWE:** CWE-200 / CWE-287 / CWE-269
- **Affected Component:** OpenAM `< 16.1.4` (`14.0.0` through `16.1.3`)
- **Patched Version:** `16.1.4+`
- **Target Ports:** `8080`, `8443`, `443`, `80`, `9443`

---

## Vulnerability Summary
1. **`CVE-2026-123551` (CVSS 10.0):** OpenAM from `14.0.0` before `16.1.4` contains an information disclosure vulnerability allowing unauthenticated attackers to read live `iPlanetDirectoryPro` session tokens from the notification WebSocket by bypassing the agent-only check via an unvalidated internal forward on legacy Liberty ID-FF endpoints.
2. **`CVE-2026-123550` (CVSS 9.3):** OpenAM before `16.1.4` contains an authentication bypass in its SAML v2.0 Service Provider accepting unsigned assertions on ECP (PAOS) and HTTP-Artifact bindings when `WantAssertionsSigned` is false.
3. **`CVE-2026-123549` (CVSS 9.3):** OpenAM before `16.1.4` fails to enforce the Valid Creation Attributes list during self-registration, allowing anonymous attackers to join administrative groups.

This plugin performs a **strictly non-intrusive, read-only check** by inspecting the public OpenAM HTTP endpoints (`/openam/json/serverinfo/version`, `/am/json/serverinfo/version`, `/openam/XUI/`, `/openam/`) and version headers (`X-OpenAM-Version`).

---

## Usage
```bash
# Audit standard OpenAM ports (8080, 8443, 443, 80, 9443)
python plugins/openam/openam_cve_2026_123551_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/openam/openam_cve_2026_123551_audit.py <target_ip> -p 8080 8443 --timeout 5.0
```

---

## Remediation
1. **Upgrade OpenAM:** Immediately update OpenAM to version **`16.1.4`** or later.
2. **Restrict Legacy Endpoints:** Block external access to legacy Liberty ID-FF endpoints and notification WebSockets at the edge reverse proxy.
3. **Hardening:** Enforce `WantAssertionsSigned=true` on SAML v2.0 Service Provider configurations and disable anonymous self-registration if unused.
