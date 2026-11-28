# TRENDnet TEW-751DR & TEW-733GR — CVE-2026-138004 & CVE-2026-138003 Passive Firmware Audit

## Overview
Passive compliance plugin verifying whether a **TRENDnet TEW-751DR** or **TEW-733GR** router runs firmware affected by **CVE-2026-138004** (CVSS 9.3, Critical) and **CVE-2026-138003** (CVSS 9.0, Critical).

## Affected & Fixed Versions
| Product | CVE | Affected Firmware | Remediation |
| :--- | :--- | :--- | :--- |
| TRENDnet TEW-751DR & TEW-733GR | CVE-2026-138004 | `<= 1.03B01` | `1.03B02+` / Disable UPnP |
| TRENDnet TEW-751DR | CVE-2026-138003 | `<= 1.03B01` | `1.03B02+` / Disable UPnP |

## Usage
```bash
python3 plugins/trendnet_tew/trendnet_tew_cve_2026_138004_audit.py --target http://192.168.10.1 --version 1.03B01
```
