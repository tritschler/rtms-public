# PHP Core Stale Global State RCE Auditor (CVE-2026-109619 / PHP2Shell)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.2_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--109619-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect web endpoints, application servers, and FastCGI/PHP-FPM services executing PHP core runtime instances vulnerable to **CVE-2026-109619** ("PHP2Shell").

---

## 🔍 Vulnerability Summary (CVE-2026-109619)

* **Severity**: **Critical (CVSS 9.2)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **CWE**: CWE-416 (Use-After-Free) / CWE-672 (Operation on Resource after Expiration or Release)
* **Affected Ecosystems**: Apache `mod_php`, PHP-FPM, Nginx FastCGI workers, LiteSpeed, Palo Alto PAN-OS web management interfaces, and containerized PHP workloads.

### Flaw Mechanics
PHP engine maintains global state structures that temporarily point directly into request-allocated memory pools. In scenarios where request execution terminates abnormally (such as memory exhaustion `memory_limit`, abortive multipart/form-data upload bailout, or unhandled `longjmp`), this global state is either not properly purged or is repopulated after being reset.

Consequently, persistent worker processes (e.g. PHP-FPM worker pools or persistent web server threads) retain dangling pointers to freed request memory. Subsequent incoming HTTP requests processed by the same worker read, modify, or branch upon this stale state before full re-initialization, leading to deterministic memory corruption and arbitrary **Remote Code Execution (RCE)** without authentication.

---

## 📋 Affected PHP Branches & Patched Thresholds

| PHP Branch | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **PHP 8.5** | Active | `8.5.0` – `8.5.11` | **`8.5.12+`** |
| **PHP 8.4** | Active | `8.4.0` – `8.4.26` | **`8.4.27+`** |
| **PHP 8.3** | Active | `8.3.0` – `8.3.35` | **`8.3.36+`** |
| **PHP 8.2** | Active | `8.2.0` – `8.2.34` | **`8.2.35+`** |
| **PHP 8.1 & older** | **End-of-Life (EOL)** | All releases (`<= 8.1.31`, `7.x`, `5.x`) | *No official upstream patch* (Vulnerable) |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (pure standard Python library: `http.client`, `socket`, `ssl`, `re`).

### Run Audit Against Any Target

Audit standard HTTP/HTTPS ports (80, 443, 8080, 8443):
```bash
python php2shell_cve_2026_109619_audit.py your-domain.com
```

Audit custom web, microservice, or FastCGI/PHP-FPM ports:
```bash
python php2shell_cve_2026_109619_audit.py 192.168.1.50 -p 80 443 8000 8088 8888 9000
```

Configure connection timeout:
```bash
python php2shell_cve_2026_109619_audit.py api.internal.corp -p 443 --timeout 5.0
```

### Exit Codes & Outputs
* **`0`**: Host is safe / running patched PHP version or non-PHP service.
* **`0`**: Warning issued (PHP detected with concealed headers via `expose_php = Off`).
* **`1`**: Critical vulnerability detected (vulnerable PHP version confirmed).

**Vulnerable Target Output:**
```text
========================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-109619 Auditor (PHP2Shell)
    Target:  web-staging.corp.local
    Ports:   80, 443
========================================================================

❌ [VULNERABLE - CRITICAL] web-staging.corp.local is vulnerable to CVE-2026-109619!

CRITICAL VULNERABILITY (CVE-2026-109619 - CVSS 9.2):
The target host web-staging.corp.local executes a vulnerable PHP core runtime version.
Flaw Overview: PHP core engine fails to reset or repopulates global state pointers pointing
into request memory across abnormal request terminations. Subsequent worker requests reusing
the thread/process will access stale, freed memory, enabling remote memory corruption and
arbitrary code execution (RCE).

Vulnerable Endpoints:
- [Port 80] PHP 8.3.15 detected via Header 'X-Powered-By: PHP/8.3.15'. Result: PHP 8.3.15 is vulnerable to CVE-2026-109619 (requires >= 8.3.36).

Remediation:
1. Immediately upgrade PHP to fixed releases: 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+.
2. Retire or backport patches for all EOL PHP branches (5.x, 7.x, 8.0.x, 8.1.x).
3. Restrict administrative endpoints and monitor FastCGI/PHP-FPM worker cycles.
```

**Safe Target Output:**
```text
========================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-109619 Auditor (PHP2Shell)
    Target:  production-api.corp.local
    Ports:   443
========================================================================

✅ [SAFE] production-api.corp.local passed audit.
   Safe: PHP services detected on production-api.corp.local are running patched versions resistant to CVE-2026-109619:
- [Port 443] PHP 8.3.36 detected via Header 'X-Powered-By: PHP/8.3.36'. Result: PHP 8.3.36 is patched against CVE-2026-109619 (patched in 8.3.36+).
```

---

## 💡 Remediation
1. **Apply Official Upstream Security Patches**:
   * Upgrade to **PHP 8.2.35**, **PHP 8.3.36**, **PHP 8.4.27**, or **PHP 8.5.12** immediately.
2. **Decommission End-of-Life PHP Deployments**:
   * PHP 7.x, 8.0, and 8.1 do not receive official security updates. Migrate workloads to supported branches or apply vendor-provided enterprise backports (e.g., Red Hat, Debian LTS, Ubuntu Pro).
3. **Hardening**:
   * Set `expose_php = Off` in `php.ini` to prevent trivial automated fingerprinting.
   * Configure aggressive PHP-FPM process respawning (`pm.max_requests = 500`) to mitigate worker stale state longevity.
