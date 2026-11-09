# WordPress Contact Form 7 Version Compliance Audit (CVE-2026-114432)

[![Severity: Critical 9.8](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/vuln/detail/CVE-2026-114432)
[![Target: Contact Form 7 < 6.2.4](https://img.shields.io/badge/Affected-<_6.2.4-orange.svg)]()
[![Patched: >= 6.2.4](https://img.shields.io/badge/Patched->=_6.2.4-brightgreen.svg)]()

## Overview

This plugin provides a passive, non-intrusive HTTP/HTTPS version compliance audit for WordPress installations running the **Contact Form 7** plugin (`< 6.2.4`), helping administrators verify patch status for **CVE-2026-114432**.

- **CVE ID**: `CVE-2026-114432`
- **CVSS Score**: `9.8 CRITICAL`
- **Affected Versions**: `< 6.2.4`
- **Patched Versions**: `>= 6.2.4`

## Passive Detection Method

1. Inspects HTML asset references (`/wp-content/plugins/contact-form-7/...?ver=X.Y.Z`).
2. Reads static plugin metadata (`/wp-content/plugins/contact-form-7/readme.txt`, `styles.css`, `index.js`) to extract `Stable tag` or header versions.
3. Compares the detected version against the patched threshold (`6.2.4`).

## Standalone Usage

```bash
python plugins/wordpress/wp_contact_form_7/wp_contact_form_7_cve_2026_114432_audit.py <target> -p 80 443
```

## Remediation

- Update **Contact Form 7** to version **6.2.4** or later.
- Ensure directory indexing and script execution are disabled inside `wp-content/uploads/wpcf7_uploads/`.
