# SolarWinds Serv-U — CVE-2026-123172 (and 8 others) Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **SolarWinds Serv-U** MFT / FTP server is affected by 9 critical vulnerabilities (up to CVSS 9.1) patched in SolarWinds Serv-U `2026.4`:
- `CVE-2026-123172`, `CVE-2026-123168`, `CVE-2026-123167`
- `CVE-2026-82322`, `CVE-2026-82321`, `CVE-2026-82320`, `CVE-2026-82319`, `CVE-2026-82316`, `CVE-2026-82315`

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| SolarWinds Serv-U | `<= 2026.3` (including `15.5.x` and earlier) | `2026.4` |

## Usage
```bash
python3 plugins/solarwinds_servu/solarwinds_servu_cve_2026_123172_audit.py --target https://mft.example.local
```
