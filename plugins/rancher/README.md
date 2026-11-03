# SUSE Rancher Manager Meta-Proxy & Fleet Audit (`CVE-2026-88811` / `CVE-2026-94290`)

## Overview
- **CVEs:** `CVE-2026-88811` (CVSS 9.1 Critical) & `CVE-2026-94290` (CVSS 9.1 Critical)
- **Affected Component:** SUSE Rancher Manager (`2.13.0`–`2.13.11`, `2.14.0`–`2.14.7`, `2.15.0`–`2.15.3`) and Rancher Fleet
- **Patched Versions:** `>= 2.13.12`, `>= 2.14.8`, `>= 2.15.4`
- **Target Ports:** `80`, `443`, `8080`, `8443`, `9443`

## Vulnerability Summary
1. **`CVE-2026-88811` (CVSS 9.1):** Missing filtering in the SUSE Rancher Manager meta-proxy (`/meta/proxy`) causes passed-in Rancher credentials and bearer tokens to be leaked to external cloud providers.
2. **`CVE-2026-94290` (CVSS 9.1):** SUSE Rancher Fleet controllers fail to restrict which `kubeconfig` secrets a Fleet `Cluster` object can reference, allowing cross-namespace privilege escalation and cluster takeover.

## Usage
```bash
python plugins/rancher/rancher_cve_2026_88811_audit.py <target_ip> -p 443 8443
```
