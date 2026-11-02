# pgAdmin 4 psql \copy RCE & Lockout Bypass Auditor (CVE-2026-116241 / CVE-2026-116238)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.4_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--116241-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **pgAdmin 4** (Server Mode) deployments (`< 9.19`) vulnerable to **CVE-2026-116241** (`psql \copy (...) TO PROGRAM` Remote Code Execution) and **CVE-2026-116238** (Flask-Security `MAX_LOGIN_ATTEMPTS` Account Lockout Bypass).

---

## 🔍 Vulnerability Summary (CVE-2026-116241 & CVE-2026-116238)

* **Severity**: **Critical (CVSS 9.4)** — ` CVE-2026-116241 ` & **Critical (CVSS 9.2)** — ` CVE-2026-116238 `
* **CWE**: CWE-78 (OS Command Injection) / CWE-287 (Improper Authentication)
* **Affected Ecosystems**: All **pgAdmin 4 Server Mode** deployments (Docker `dpage/pgadmin4`, Kubernetes, Ubuntu/Debian/RHEL packages, Python wheels) running versions prior to **`9.19`**.

### Flaw Mechanics
1. **`CVE-2026-116241` (CVSS 9.4 — Remote Code Execution via `psql \copy` Wrapper Escape)**:
   pgAdmin 4's *Import/Export Data* tool wraps a user's query export in a `psql \copy (...) TO` command and checks that the query's parentheses are balanced so nothing can escape the wrapper. While the check rejected a backslash inside a single-quoted string, it failed to reject a backslash inside a double-quoted identifier (`\"`). With `standard_conforming_strings = off` (which any ordinary database role can set for its session), `psql`'s `\copy` parser treats `\"` as an escaped quote rather than closing the identifier. This causes pgAdmin's and `psql`'s view of quoting to diverge, allowing a closing parenthesis to terminate the `\copy (...)` wrapper and execute an arbitrary **`TO PROGRAM`** OS command on the pgAdmin 4 server host (bypass of `CVE-2026-17566`).
2. **`CVE-2026-116238` (CVSS 9.2 — Unauthenticated Account Lockout Bypass)**:
   In Server Mode, pgAdmin 4 locks internal accounts after `MAX_LOGIN_ATTEMPTS` failed logins (3 by default). Because Flask-Security registered its own raw views (`/login`, `/verify`, `/change`, `/reset`) alongside pgAdmin's views and pgAdmin matched internal usernames case-sensitively during lockout checks while authenticating emails case-insensitively, unauthenticated remote attackers can perform unlimited password brute-force attacks against any internal account, including the primary administrator.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **pgAdmin 4 (`pgadmin_4`)** | Active | All releases **`< 9.19`** (`<= 9.18`, `8.x`, `7.x`) | **`9.19+`** |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (pure standard Python library: `http.client`, `socket`, `ssl`, `re`).

### Run Audit Against Any Target

Audit standard HTTP/HTTPS and pgAdmin ports (`80, 443, 5050, 8080, 8443`):
```bash
python pgadmin4_cve_2026_116241_audit.py pgadmin.your-domain.com
```

Audit custom ports:
```bash
python pgadmin4_cve_2026_116241_audit.py 192.168.1.50 -p 80 443 5050 5051 8080 8888
```

Configure connection timeout:
```bash
python pgadmin4_cve_2026_116241_audit.py db-admin.internal.corp -p 5050 --timeout 5.0
```

### Exit Codes & Outputs
* **`0`**: Host is safe (patched `pgAdmin 4 >= 9.19` or non-pgAdmin service).
* **`0`**: Warning issued (`pgAdmin 4` detected with concealed version strings).
* **`1`**: Critical vulnerability detected (`pgAdmin 4 < 9.19` confirmed).

**Vulnerable Target Output:**
```text
============================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-116241 Auditor (pgAdmin 4)
    Target:  db-admin.corp.local
    Ports:   80, 443, 5050
============================================================================

❌ [VULNERABLE - CRITICAL] db-admin.corp.local is vulnerable to CVE-2026-116241 / CVE-2026-116238!

CRITICAL VULNERABILITY (CVE-2026-116241 CVSS 9.4 / CVE-2026-116238 CVSS 9.2):
The target host db-admin.corp.local runs a vulnerable pgAdmin 4 Server Mode version (< 9.19).

Vulnerable Endpoints:
- [Port 5050] pgAdmin 4 v9.18 detected via HTTP GET /login (asset/page version metadata). Result: pgAdmin 4 9.18 is vulnerable to CVE-2026-116241 (CVSS 9.4 RCE via psql \copy wrapper escape) and CVE-2026-116238 (CVSS 9.2 Flask-Security /login lockout bypass). Affected: < 9.19; requires upgrade to >= 9.19.

Remediation:
1. Immediately upgrade pgAdmin 4 to version 9.19 or later.
2. Restrict network access to pgAdmin 4 behind a VPN or reverse proxy with MFA.
3. Block external access to Flask-Security fallback routes (/verify, /change, /reset) if unpatched.
```

---

## 💡 Remediation
1. **Upgrade to pgAdmin 4 `9.19` or Later**:
   * Pull the latest container image (`docker pull dpage/pgadmin4:9.19` or `dpage/pgadmin4:latest`) or update via system packages (`apt` / `dnf` / `pip install --upgrade pgadmin4>=9.19`).
2. **Restrict Network Exposure**:
   * Do not expose pgAdmin 4 Server Mode directly to the public Internet; place it behind a WireGuard VPN or Zero-Trust reverse proxy.
