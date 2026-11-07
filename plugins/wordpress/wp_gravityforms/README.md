# WordPress Gravity Forms PHP Object Injection Auditor (CVE-2026-103039)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.8_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--103039-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect WordPress web servers running vulnerable versions of the **Gravity Forms** plugin (`<= 3.1.2`) exposed to **CVE-2026-103039**.

---

## 🔍 Vulnerability Summary (CVE-2026-103039)

* **Severity**: **Critical (CVSS 9.8)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE**: CWE-502 (Deserialization of Untrusted Data)
* **Affected Ecosystems**: WordPress sites using the **Gravity Forms** plugin (`gravityforms`) in versions up to and including `3.1.2`.

### Flaw Mechanics
The Gravity Forms plugin for WordPress is vulnerable to **PHP Object Injection** in all versions up to, and including, **`3.1.2`** via a **Post Custom Field** whose input type is **`List`**.

Specifically, `GFFormsModel::create_post()` passes the user-submitted field value directly to WordPress's unrestricted global `maybe_unserialize()` function instead of the plugin's own hardened `GFCommon::maybe_unserialize()` helper (which was introduced in `3.1.1` and passes `allowed_classes => false` specifically to prevent object injection).

Because forms containing a *Post Custom Field (List)* can be submitted by unauthenticated visitors, remote attackers can supply crafted serialized PHP objects. When combined with any POP (Property-Oriented Programming) gadget chain present in WordPress core, installed plugins, or active themes, exploitation leads to **unauthenticated Remote Code Execution (RCE)**, arbitrary file deletion, or sensitive database exfiltration.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **Gravity Forms (`gravityforms`)** | Active | All releases **`<= 3.1.2`** (`1.x`, `2.x`, `3.0.x`, `3.1.0` – `3.1.2`) | **`3.1.3+`** |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (pure standard Python library: `http.client`, `socket`, `ssl`, `re`).

### Run Audit Against Any Target

Audit standard HTTP/HTTPS ports (`80, 443, 8080, 8443`):
```bash
python wp_gravityforms_cve_2026_103039_audit.py your-wordpress-site.com
```

Audit custom web ports:
```bash
python wp_gravityforms_cve_2026_103039_audit.py 192.168.1.50 -p 80 443 8000 8088 8888
```

Configure connection timeout:
```bash
python wp_gravityforms_cve_2026_103039_audit.py portal.internal.corp -p 443 --timeout 5.0
```

### Exit Codes & Outputs
* **`0`**: Host is safe (patched Gravity Forms `>= 3.1.3` or Gravity Forms not installed).
* **`0`**: Warning issued (Gravity Forms detected with concealed version strings).
* **`1`**: Critical vulnerability detected (vulnerable Gravity Forms `<= 3.1.2` confirmed).

**Vulnerable Target Output:**
```text
============================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-103039 Auditor (Gravity Forms)
    Target:  cms-prod.corp.local
    Ports:   80, 443
============================================================================

❌ [VULNERABLE - CRITICAL] cms-prod.corp.local is vulnerable to CVE-2026-103039!

CRITICAL VULNERABILITY (CVE-2026-103039 - CVSS 9.8):
The target host cms-prod.corp.local runs a vulnerable version of the WordPress Gravity Forms plugin (<= 3.1.2).
Flaw Overview: Gravity Forms is vulnerable to PHP Object Injection via a Post Custom Field whose
input type is 'List'. GFFormsModel::create_post() passes the submitted value to WordPress's
unrestricted global maybe_unserialize() instead of the hardened GFCommon::maybe_unserialize()
(which enforces allowed_classes => false). Unauthenticated attackers can inject arbitrary PHP objects
to achieve remote code execution (RCE), arbitrary file deletion, or sensitive data exposure.

Vulnerable Endpoints:
- [Port 443] Gravity Forms 3.1.2 detected via HTML asset reference (/wp-content/plugins/gravityforms/...?ver=). Result: Gravity Forms 3.1.2 is vulnerable to CVE-2026-103039 (affected: <= 3.1.2; requires upgrade to >= 3.1.3).

Remediation:
1. Immediately update the Gravity Forms WordPress plugin to version 3.1.3 or later.
2. Audit public forms utilizing 'Post Custom Field' with the 'List' input type.
3. Restrict access to /wp-content/plugins/gravityforms/ metadata files via WAF/web server rules.
```

---

## 💡 Remediation
1. **Update Gravity Forms Immediately**:
   * Upgrade the **Gravity Forms** plugin to **`3.1.3`** or later via **WP-Admin > Plugins** or WP-CLI (`wp plugin update gravityforms`).
2. **Audit Publicly Exposed Forms**:
   * Review any active forms using **Post Custom Fields** with the **List** input type and disable public unauthenticated submissions until patched.
3. **Web Server Hardening**:
   * Block direct public HTTP access to `/wp-content/plugins/gravityforms/change_log.txt`, `changelog.txt`, and `readme.txt` to prevent version disclosure.
