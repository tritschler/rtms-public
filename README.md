# RTMS Community Security Plugins & Fast-Response Auditors

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-RTMS_Suite-blue.svg)](https://3ts.ai)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-Open_Source_Security-orange.svg)]()

Welcome to the official **RTMS Community Plugins** repository. This open-source hub contains standalone security audit tools and modular detection plugins engineered for the **[RTMS Cybersecurity Suite](https://3ts.ai)** (Real-Time Monitoring & Security).

Each plugin is developed to provide rapid, reliable, and non-destructive detection of critical emerging vulnerabilities, zero-days, and cryptographic flaws across enterprise networks.

---

## 📚 Available Security Plugins

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory | Quick Audit Command |
|:---|:---:|:---:|:---|:---:|:---|
| **eMudhra Weak Intermediate CA Audit** | **CVE-2026-91403** | `CRITICAL 9.1` | WebPKI, Java JSSE, TLS endpoints | [`plugins/emudhra_weak_ca/`](plugins/emudhra_weak_ca/) | `python plugins/emudhra_weak_ca/emudhra_weak_ca_audit.py <target>` |
| **PHP Core Stale Global State RCE Audit (PHP2Shell)** | **CVE-2026-109619** | `CRITICAL 9.2` | PHP 5.4 to 8.5.11, FastCGI, PAN-OS | [`plugins/php2shell/`](plugins/php2shell/) | `python plugins/php2shell/php2shell_cve_2026_109619_audit.py <target>` |
| **WordPress Gravity Forms PHP Object Injection Audit** | **CVE-2026-103039** | `CRITICAL 9.8` | WordPress Gravity Forms `<= 3.1.2` | [`plugins/wp_gravityforms/`](plugins/wp_gravityforms/) | `python plugins/wp_gravityforms/wp_gravityforms_cve_2026_103039_audit.py <target>` |
| **vsftpd FTPS Data Channel Hijacking Audit** | **CVE-2026-119568** | `CRITICAL 9.1` | vsftpd `<= 3.0.5` (Ubuntu, Debian, RHEL) | [`plugins/vsftpd/`](plugins/vsftpd/) | `python plugins/vsftpd/vsftpd_cve_2026_119568_audit.py <target>` |
| **pgAdmin 4 psql \copy RCE & Lockout Bypass Audit** | **CVE-2026-116241** | `CRITICAL 9.4` | pgAdmin 4 Server Mode `< 9.19` | [`plugins/pgadmin4/`](plugins/pgadmin4/) | `python plugins/pgadmin4/pgadmin4_cve_2026_116241_audit.py <target>` |
| **SUSE Rancher Manager Meta-Proxy & Fleet Audit** | **CVE-2026-88811** | `CRITICAL 9.1` | SUSE Rancher `2.13`–`2.15` (`< 2.13.12`/`2.14.8`/`2.15.4`) | [`plugins/rancher/`](plugins/rancher/) | `python plugins/rancher/rancher_cve_2026_88811_audit.py <target>` |
| **Zoho ManageEngine Log360 & EventLog Analyzer Audit** | **CVE-2026-13594** | `CRITICAL 9.1` | ManageEngine Log360 & EventLog Analyzer `<= 13062` | [`plugins/manageengine_log360/`](plugins/manageengine_log360/) | `python plugins/manageengine_log360/manageengine_cve_2026_13594_audit.py <target>` |
| **Barracuda Email Security Gateway Auth Bypass Audit** | **CVE-2026-116606** | `CRITICAL 9.3` | Barracuda Email Security Gateway `< 9.4.0.030` | [`plugins/barracuda_esg/`](plugins/barracuda_esg/) | `python plugins/barracuda_esg/barracuda_esg_cve_2026_116606_audit.py <target>` |
| **SonicWall GMS Unauthenticated Internal File Read Audit** | **CVE-2026-109593** | `CRITICAL 9.1` | SonicWall Global Management System `<= 9.5.2` | [`plugins/sonicwall_gms/`](plugins/sonicwall_gms/) | `python plugins/sonicwall_gms/sonicwall_gms_cve_2026_109593_audit.py <target>` |

---

## 🗂️ Repository Structure

The repository follows a clean, modular structure where each plugin is self-contained with its dedicated technical documentation:

```text
rtms-public/
├── LICENSE                                # MIT Open-Source License
├── README.md                              # This catalog & community guide
├── pyproject.toml                         # Unified test & package configuration
├── requirements.txt                       # Consolidated Python dependencies
│
├── plugins/                               # Dedicated security plugins directory
│   ├── emudhra_weak_ca/                   # eMudhra Weak Intermediate CA Audit (CVE-2026-91403)
│   │   ├── README.md                      # Detailed vulnerability analysis & guidance
│   │   └── emudhra_weak_ca_audit.py       # Standalone CLI & RTMS BasePlugin script
│   │
│   ├── php2shell/                         # PHP Core Stale Global State RCE (CVE-2026-109619)
│   │   ├── README.md                      # Detailed vulnerability analysis & guidance
│   │   └── php2shell_cve_2026_109619_audit.py # Standalone CLI & RTMS BasePlugin script
│   │
│   ├── wp_gravityforms/                   # WordPress Gravity Forms PHP Object Injection (CVE-2026-103039)
│   │   ├── README.md                      # Detailed vulnerability analysis & guidance
│   │   └── wp_gravityforms_cve_2026_103039_audit.py # Standalone CLI & RTMS BasePlugin script
│   │
│   ├── vsftpd/                            # vsftpd FTPS Data Channel Hijacking (CVE-2026-119568)
│   │   ├── README.md                      # Detailed vulnerability analysis & guidance
│   │   └── vsftpd_cve_2026_119568_audit.py # Standalone CLI & RTMS BasePlugin script
│   │
│   └── pgadmin4/                          # pgAdmin 4 psql \copy RCE & Lockout Bypass (CVE-2026-116241)
│       ├── README.md                      # Detailed vulnerability analysis & guidance
│       └── pgadmin4_cve_2026_116241_audit.py # Standalone CLI & RTMS BasePlugin script
│
├── tests/                                 # Automated unit test suite
│   ├── test_audit.py                      # Tests for eMudhra CA auditor
│   ├── test_php2shell_audit.py            # Tests for PHP2Shell auditor
│   ├── test_wp_gravityforms_audit.py      # Tests for WordPress Gravity Forms auditor
│   ├── test_vsftpd_audit.py               # Tests for vsftpd FTPS auditor
│   └── test_pgadmin4_audit.py             # Tests for pgAdmin 4 auditor
```

---

## 🚀 Quick Start (Standalone CLI Mode)

All plugins in this repository can be run directly from any terminal without requiring an active RTMS server deployment:

### 1. Installation

```bash
git clone https://github.com/tritschler/rtms-public.git
cd rtms-public
pip install -r requirements.txt
```

### 2. Running an Audit

You can execute plugins directly from their respective directory or from the repository root:

```bash
# Audit a host for compromised eMudhra intermediate TLS certificates (CVE-2026-91403)
python plugins/emudhra_weak_ca/emudhra_weak_ca_audit.py target-server.com -p 443 8443

# Audit a host for vulnerable PHP core runtime instances (CVE-2026-109619 / PHP2Shell)
python plugins/php2shell/php2shell_cve_2026_109619_audit.py 192.168.1.10 -p 80 443 8080 9000

# Audit a WordPress host for vulnerable Gravity Forms plugin versions (CVE-2026-103039)
python plugins/wp_gravityforms/wp_gravityforms_cve_2026_103039_audit.py 192.168.1.20 -p 80 443

# Audit an FTP/FTPS server for vsftpd data channel hijacking (CVE-2026-119568)
python plugins/vsftpd/vsftpd_cve_2026_119568_audit.py 192.168.1.30 -p 21 990

# Audit a pgAdmin 4 server for psql \copy RCE & lockout bypass (CVE-2026-116241 / CVE-2026-116238)
python plugins/pgadmin4/pgadmin4_cve_2026_116241_audit.py 192.168.1.40 -p 80 443 5050
```

---

## 🔌 Integration with RTMS Cybersecurity Suite

Plugins from this repository integrate natively with **RTMS Suite**:

### Option 1: File Drop into RTMS Scanner Probe
1. Copy desired plugin scripts into the `external_plugins/` directory of your scanner probe:
   ```bash
   cp plugins/php2shell/php2shell_cve_2026_109619_audit.py /opt/rtms-scanner/external_plugins/
   ```
2. The dynamic RTMS plugin loader automatically analyzes code via AST security guardrails and activates the plugin.
3. Every **Deep Scan** cycle across monitored subnets will automatically execute the checks and post findings to your dashboard.

### Option 2: Upload via RTMS Web UI
1. Navigate to **Administration > Plugins** in the RTMS Web Console.
2. Upload the Python plugin file.
3. The plugin immediately becomes available for:
   * **Automated subnet discovery cycles**
   * **Targeted Plugin Audits (Surgical IP Verification)** directly from **Asset Management** or the **Plugins Catalog**.

---

## 🛠️ Contributing a New Plugin

We welcome contributions from security researchers, network engineers, and system administrators! 

👉 **Detailed Developer Guide & Template:** Please read our full **[`CONTRIBUTING.md`](CONTRIBUTING.md)** for detailed specifications, AST security guardrails, unit test guidelines, and a copy-pasteable plugin template.

### Quick Checklist:
1. **Directory Structure**: Create a dedicated subfolder `plugins/<plugin_slug>/` containing `<plugin_slug>_audit.py` and a comprehensive `README.md`.
2. **Contract Compliance**:
   * Inherit from `BasePlugin` (with standalone fallback).
   * Declare metadata in `self.info` (`name`, `description`, `severity`, `cve`, `version`).
   * Implement `check_requirements(target_ip, target_services) -> bool`.
   * Implement `run_audit(target_ip, target_services, credentials=None) -> Dict[str, Any]` returning `self.format_result(status, proof, details)`.
3. **AST Security**: Strictly read-only; no `subprocess`, `os.system`, `ctypes`, `eval`, `exec`, or file writing/tampering operations.
4. **Automated Tests**: Add unit tests in `tests/test_<plugin_slug>.py` and verify with:
   ```bash
   uv run --extra dev pytest
   ```

---

## 🛡️ About RTMS (Real-Time Monitoring & Security)

Published with ❤️ by **[3TS Consulting SRL](https://3ts.ai)**, the team behind **RTMS**.

**RTMS** is a sovereign European cybersecurity and network posture management platform engineered for continuous asset visibility, threat detection, and regulatory compliance:
* **Zero Telemetry Leakage**: On-premise air-gapped vulnerability correlation.
* **Continuous Asset Discovery**: Passive ARP auditing, rogue AP (*Evil Twin*) detection, and non-disruptive fingerprinting.
* **Compliance Assurance**: Automated evidence collection and governance workflows for **NIS 2 Directive (EU 2022/2555)** and **Cyber Resilience Act (CRA - EU 2024/2847)**.

👉 **Explore the full enterprise platform:** [https://3ts.ai](https://3ts.ai)  
📧 **Contact & Security Inquiries:** [contact@3ts.ai](mailto:contact@3ts.ai)

---

## ⚖️ License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

Copyright &copy; 2026 **RTMS Project Contributors / 3TS Consulting SRL**.
