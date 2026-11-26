# Wing FTP Server — CVE-2026-135171 Passive Version Audit

## Overview
Passive compliance plugin verifying whether a **Wing FTP Server** installation is affected by **CVE-2026-135171** (CVSS 9.2, Critical), a predictable administrator session ID vulnerability in versions prior to `8.2.8`.

## Affected & Fixed Versions
| Product | Affected Versions | Patched Version |
| :--- | :--- | :--- |
| Wing FTP Server | `< 8.2.8` (`<= 8.2.7`) | `8.2.8` |

## Usage
```bash
python3 plugins/wing_ftp_server/wing_ftp_server_cve_2026_135171_audit.py --target http://ftp.example.local:5466
```
