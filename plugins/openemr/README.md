# OpenEMR Multi-CVE Version Compliance Audit (CVE-2026-124445 / CVE-2026-124490)

[![Severity: Critical 9.4](https://img.shields.io/badge/CVSS_v4.0-9.4_CRITICAL-red.svg)](https://nvd.nist.gov/vuln/detail/CVE-2026-124445)
[![Target: OpenEMR < 8.4.0](https://img.shields.io/badge/Affected-<_8.4.0-orange.svg)]()
[![Patched: >= 8.4.0](https://img.shields.io/badge/Patched->=_8.4.0-brightgreen.svg)]()

## Overview

This plugin performs a passive, non-intrusive HTTP/HTTPS version compliance check for **OpenEMR** installations to verify patch status across 5 critical CVEs:

- **CVE-2026-124445** (`CVSS 9.3`): Affected `7.0.1` to `< 8.4.0` (fixed in `8.4.0+`)
- **CVE-2026-124490** (`CVSS 9.4`): Affected `< 8.3.0` (fixed in `8.3.0+`)
- **CVE-2026-124469** (`CVSS 9.4`): Affected `< 8.3.0` (fixed in `8.3.0+`)
- **CVE-2026-124463** (`CVSS 9.3`): Affected `< 8.3.0` (fixed in `8.3.0+`)
- **CVE-2026-124450** (`CVSS 9.3`): Affected `< 8.3.0` (fixed in `8.3.0+`)

## Standalone Usage

```bash
python plugins/openemr/openemr_cve_2026_124445_audit.py <target> -p 80 443 8300 9300
```

## Remediation

- Upgrade **OpenEMR** to version **8.4.0** or later.
- Restrict external network access to `/admin.php`.
