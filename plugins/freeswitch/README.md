# FreeSWITCH SIP & WebRTC Stack Version Audit (`CVE-2026-116779` / `CVE-2026-116785` / `CVE-2026-116790`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--116779-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **SignalWire FreeSWITCH** instances (`< 1.11.3`) exposed to **CVE-2026-116779**, **CVE-2026-116785**, and **CVE-2026-116790**.

---

## Overview
- **CVE:** `CVE-2026-116779` (CVSS 9.8 Critical), `CVE-2026-116785` (CVSS 9.1), `CVE-2026-116790` (CVSS 9.1)
- **Severity:** **Critical (CVSS 9.8)**
- **Affected Component:** SignalWire FreeSWITCH versions prior to `1.11.3` (`< 1.11.3`)
- **Patched Version:** `1.11.3+`
- **Target Ports:** `5060`, `5061`, `5080`, `7443`, `8080`

---

## Vulnerability Summary
**FreeSWITCH prior to `1.11.3`** is affected by three critical vulnerabilities:
1. **CVE-2026-116779 (CVSS 9.8):** `sofia_presence_handle_sip_i_message()` splits the `To` user of an inbound SIP `MESSAGE` on a plus sign and treats the left side as a chat protocol selector, allowing unauthorized API invocation via `switch_api_execute()`.
2. **CVE-2026-116785 (CVSS 9.1):** `ws_read_frame()` improperly narrows 64-bit extended payload lengths on `mod_xml_rpc` WebSocket endpoints, leading to buffer overwrite and daemon crash.
3. **CVE-2026-116790 (CVSS 9.1):** Inbound ICE connectivity checks are accepted without cryptographically validating the STUN `MESSAGE-INTEGRITY` attribute unless `ice_verify_message_integrity=true` is configured in `1.11.2+`.

This plugin performs a **strictly non-intrusive, read-only check** by sending a standard `SIP OPTIONS` health check or HTTP `GET /` request to inspect the `User-Agent` / `Server` version header (`FreeSWITCH-mod_sofia/<version>`).

---

## Usage
```bash
# Audit standard FreeSWITCH SIP and HTTP/WSS ports (5060, 5061, 5080, 7443, 8080)
python plugins/freeswitch/freeswitch_cve_2026_116779_audit.py <target_ip>

# Audit custom ports with a specific timeout
python plugins/freeswitch/freeswitch_cve_2026_116779_audit.py <target_ip> -p 5060 5080 --timeout 5.0
```

---

## Remediation
1. **Upgrade FreeSWITCH:** Immediately update FreeSWITCH to version **`1.11.3`** or later.
2. **Harden SIP & ICE Profiles:** Enable `ice_verify_message_integrity=true`, disable unused `mod_xml_rpc` WebSocket listeners, and restrict inbound SIP `MESSAGE` routing to authenticated users.
