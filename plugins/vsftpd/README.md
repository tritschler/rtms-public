# vsftpd FTPS Data Channel Hijacking & Auth Bypass Auditor (CVE-2026-119568)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![CVSS Score](https://img.shields.io/badge/CVSS_v3.1-9.1_CRITICAL-red.svg)](https://nvd.nist.gov/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Target](https://img.shields.io/badge/Vulnerability-CVE--2026--119568-orange.svg)]()

A lightweight, standalone security audit tool and official plugin for **[RTMS Suite](https://3ts.ai)** to detect **vsftpd** (*Very Secure FTP Daemon*) servers (`<= 3.0.5`) vulnerable to unauthenticated FTPS data connection hijacking via **CVE-2026-119568**.

---

## 🔍 Vulnerability Summary (CVE-2026-119568)

* **Severity**: **Critical (CVSS 9.1)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
* **CWE**: CWE-287 (Improper Authentication) / CWE-384 (Session Fixation)
* **Affected Ecosystems**: Ubuntu, Debian, Red Hat Enterprise Linux (RHEL), Rocky Linux, AlmaLinux, SUSE, Alpine, and FreeBSD servers running `vsftpd` through version **`3.0.5`** with FTPS (`ssl_enable=YES`) enabled.

### Flaw Mechanics
`vsftpd` through **`3.0.5`** contains an authentication bypass vulnerability in `ssl_data_accept()` that allows unauthenticated attackers to hijack FTPS data connections (`PASV` / `EPSV`) by resuming their own TLS session ticket.

When an unauthenticated attacker connects to the control port (`21` or `990`) and initiates `AUTH TLS`, OpenSSL issues a valid TLS session ticket signed by the server's ticket key. If the attacker shares the victim's source IP address (common behind corporate NAT gateways, carrier-grade NAT, VPN concentrators, proxies, or cloud egress IPs) and connects to the victim's allocated `PASV` port while presenting their own TLS session ticket, `ssl_data_accept()` accepts the resumed TLS session without verifying that it belongs to the victim's authenticated control connection. This allows the attacker to **steal sensitive file downloads** or **inject malicious upload data**.

---

## 📋 Affected Versions & Patched Thresholds

| Component | Status | Vulnerable Versions | Patched / Safe Release |
|:---|:---:|:---:|:---:|
| **vsftpd (`vsftpd`)** | Active | All releases **`<= 3.0.5`** (`2.x`, `3.0.0` – `3.0.5`) with FTPS enabled | **`3.0.6+`** (or vendor backport) |

---

## 🚀 Usage (Standalone CLI)

### Requirements
Zero third-party dependencies required (pure standard Python library: `socket`, `ssl`, `re`).

### Run Audit Against Any Target

Audit standard FTP/FTPS ports (`21, 990, 2121`):
```bash
python vsftpd_cve_2026_119568_audit.py ftp.your-domain.com
```

Audit custom FTP ports:
```bash
python vsftpd_cve_2026_119568_audit.py 192.168.1.50 -p 21 990 2121 8021
```

Configure connection timeout:
```bash
python vsftpd_cve_2026_119568_audit.py files.internal.corp -p 21 --timeout 5.0
```

### Exit Codes & Outputs
* **`0`**: Host is safe (patched `vsftpd >= 3.0.6` or non-vsftpd service).
* **`0`**: Warning issued (`vsftpd <= 3.0.5` with `AUTH TLS` disabled, or FTPS active with concealed banner).
* **`1`**: Critical vulnerability detected (`vsftpd <= 3.0.5` with FTPS active).

**Vulnerable Target Output:**
```text
============================================================================
 🛡️  RTMS Vulnerability Scanner - CVE-2026-119568 Auditor (vsftpd FTPS)
    Target:  ftp-exchange.corp.local
    Ports:   21, 990
============================================================================

❌ [VULNERABLE - CRITICAL] ftp-exchange.corp.local is vulnerable to CVE-2026-119568!

CRITICAL VULNERABILITY (CVE-2026-119568 - CVSS 9.1):
The target host ftp-exchange.corp.local runs vsftpd <= 3.0.5 with FTPS (SSL/TLS) enabled.
Flaw Overview: vsftpd through 3.0.5 contains an authentication bypass vulnerability in
ssl_data_accept() that allows unauthenticated attackers to hijack FTPS data connections
by resuming their own TLS session ticket.

Vulnerable Endpoints:
- [Port 21] vsftpd 3.0.5 (Banner: '220 (vsFTPd 3.0.5)', FTPS: '234 Proceed with negotiation.'). Result: vsftpd 3.0.5 is vulnerable to CVE-2026-119568 (affected: <= 3.0.5; requires >= 3.0.6). FTPS is active on port 21 (234 Proceed with negotiation.), making ssl_data_accept() directly reachable.

Remediation:
1. Upgrade vsftpd to version 3.0.6 or apply your Linux distribution's security patch for CVE-2026-119568.
2. Ensure 'require_ssl_reuse=YES' is enforced in /etc/vsftpd.conf so data connections must reuse the control channel's exact TLS session.
3. Where possible, migrate file transfers from FTPS to SFTP (OpenSSH).
```

---

## 💡 Remediation
1. **Apply Official Security Updates**:
   * Upgrade `vsftpd` to **`3.0.6+`** or install the distribution backport (`apt update && apt --only-upgrade install vsftpd` / `dnf update vsftpd`).
2. **Enforce Strict TLS Session Reuse on Data Channels**:
   * In `/etc/vsftpd.conf`, set:
     ```ini
     require_ssl_reuse=YES
     ```
     and restart `vsftpd` (`systemctl restart vsftpd`).
3. **Prefer SFTP over FTPS**:
   * Where possible, replace legacy FTP/FTPS services with **SFTP** (OpenSSH subsystem), which multiplexes control and data over a single authenticated SSH channel.
