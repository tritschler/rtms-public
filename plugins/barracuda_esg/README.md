# Barracuda Email Security Gateway Auth Bypass Audit (`CVE-2026-116606`)

## Overview
- **CVE:** `CVE-2026-116606` (CVSS 9.3 Critical)
- **Affected Component:** Barracuda Email Security Gateway (ESG) versions `< 9.4.0.030`
- **Patched Version:** `>= 9.4.0.030`
- **Target Ports:** `80`, `443`, `8000`, `8443`

## Vulnerability Summary
An authentication bypass in Barracuda Email Security Gateway versions earlier than `9.4.0.030` allows an unauthenticated remote attacker to invoke a configuration-import function and restore a crafted backup archive, resulting in unauthorized modification of the appliance's global configuration.

## Usage
```bash
python plugins/barracuda_esg/barracuda_esg_cve_2026_116606_audit.py <target_ip> -p 443 8000
```
