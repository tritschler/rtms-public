# Fortinet FortiAnalyzer — CVE-2026-126229 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Fortinet FortiAnalyzer** appliance is affected by **CVE-2026-126229** (CVSS 9.1, Critical), an authorization bypass through user-controlled key (`CWE-639`).

## Affected & Fixed Versions
| Firmware Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| FortiAnalyzer 7.2 | `7.2.0` – `7.2.12` | `7.2.13` |
| FortiAnalyzer 7.4 | `7.4.0` – `7.4.11` | `7.4.12` |
| FortiAnalyzer 7.6 | `7.6.0` – `7.6.7` | `7.6.8` |
| FortiAnalyzer 8.0 | `8.0.0` – `8.0.1` | `8.0.2` |

## Usage
```bash
python3 plugins/fortianalyzer/fortianalyzer_cve_2026_126229_audit.py --target https://faz.example.local --version 7.6.7
```
