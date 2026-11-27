# Eclipse Ditto — CVE-2026-135203 Passive Version Audit

## Overview
Passive compliance plugin verifying whether an **Eclipse Ditto** digital twin framework instance is affected by **CVE-2026-135203** (CVSS 9.4, Critical), a Mozilla Rhino JavaScript sandbox escape vulnerability due to missing `ClassShutter` in the connectivity service payload mapper.

## Affected & Fixed Versions
| Release Branch | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Eclipse Ditto `0.3`–`3.8` | `0.3.0-M1` through `3.8.15` (`< 3.8.16`) | `3.8.16` |
| Eclipse Ditto `3.9.x` | `3.9.0` through `3.9.9` (`< 3.9.10`) | `3.9.10` |

## Usage
```bash
python3 plugins/eclipse_ditto/eclipse_ditto_cve_2026_135203_audit.py --target https://ditto.example.local
```
