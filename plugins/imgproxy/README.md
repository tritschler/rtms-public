# imgproxy ICO Loader Version Compliance Audit (CVE-2026-123614)

[![Severity: Critical 9.3](https://img.shields.io/badge/CVSS_v4.0-9.3_CRITICAL-red.svg)](https://nvd.nist.gov/vuln/detail/CVE-2026-123614)
[![Target: imgproxy 4.0.0 - 4.0.15](https://img.shields.io/badge/Affected-4.0.0--4.0.15-orange.svg)]()
[![Patched: >= 4.0.16](https://img.shields.io/badge/Patched->=_4.0.16-brightgreen.svg)]()

## Overview

This plugin performs a passive, read-only HTTP/HTTPS version compliance check for **imgproxy** servers (`4.0.0` before `4.0.16`) to verify patch status for **CVE-2026-123614**.

- **CVE ID**: `CVE-2026-123614`
- **CVSS Score**: `9.3 CRITICAL`
- **Affected Versions**: `4.0.0` to `4.0.15` (`< 4.0.16`)
- **Patched Versions**: `>= 4.0.16`

## Standalone Usage

```bash
python plugins/imgproxy/imgproxy_cve_2026_123614_audit.py <target> -p 8080 80 443
```

## Remediation

- Upgrade **imgproxy** to version **4.0.16** or later.
- Configure `IMGPROXY_KEY` and `IMGPROXY_SALT` to enforce URL signature verification.
