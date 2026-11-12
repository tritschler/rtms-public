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
| **WordPress Gravity Forms PHP Object Injection Audit** | **CVE-2026-103039** | `CRITICAL 9.8` | WordPress Gravity Forms `<= 3.1.2` | [`plugins/wordpress/wp_gravityforms/`](plugins/wordpress/wp_gravityforms/) | `python plugins/wordpress/wp_gravityforms/wp_gravityforms_cve_2026_103039_audit.py <target>` |
| **vsftpd FTPS Data Channel Hijacking Audit** | **CVE-2026-119568** | `CRITICAL 9.1` | vsftpd `<= 3.0.5` (Ubuntu, Debian, RHEL) | [`plugins/vsftpd/`](plugins/vsftpd/) | `python plugins/vsftpd/vsftpd_cve_2026_119568_audit.py <target>` |
| **pgAdmin 4 psql \copy RCE & Lockout Bypass Audit** | **CVE-2026-116241** | `CRITICAL 9.4` | pgAdmin 4 Server Mode `< 9.19` | [`plugins/pgadmin4/`](plugins/pgadmin4/) | `python plugins/pgadmin4/pgadmin4_cve_2026_116241_audit.py <target>` |
| **SUSE Rancher Manager Meta-Proxy & Fleet Audit** | **CVE-2026-88811** | `CRITICAL 9.1` | SUSE Rancher `2.13`–`2.15` (`< 2.13.12`/`2.14.8`/`2.15.4`) | [`plugins/rancher/`](plugins/rancher/) | `python plugins/rancher/rancher_cve_2026_88811_audit.py <target>` |
| **Zoho ManageEngine Log360 & EventLog Analyzer Audit** | **CVE-2026-13594** | `CRITICAL 9.1` | ManageEngine Log360 & EventLog Analyzer `<= 13062` | [`plugins/manageengine_log360/`](plugins/manageengine_log360/) | `python plugins/manageengine_log360/manageengine_cve_2026_13594_audit.py <target>` |
| **Barracuda Email Security Gateway Auth Bypass Audit** | **CVE-2026-116606** | `CRITICAL 9.3` | Barracuda Email Security Gateway `< 9.4.0.030` | [`plugins/barracuda_esg/`](plugins/barracuda_esg/) | `python plugins/barracuda_esg/barracuda_esg_cve_2026_116606_audit.py <target>` |
| **SonicWall GMS Unauthenticated Internal File Read Audit** | **CVE-2026-109593** | `CRITICAL 9.1` | SonicWall Global Management System `<= 9.5.2` | [`plugins/sonicwall_gms/`](plugins/sonicwall_gms/) | `python plugins/sonicwall_gms/sonicwall_gms_cve_2026_109593_audit.py <target>` |
| **GLPI Two-Factor Authentication Bypass Audit** | **CVE-2026-52848** | `CRITICAL 9.2` | GLPI `11.0.0` to `11.0.7` (`< 11.0.8`) | [`plugins/glpi/`](plugins/glpi/) | `python plugins/glpi/glpi_cve_2026_52848_audit.py <target>` |
| **Sonatype Nexus Repository 3 SAML/OIDC Account Bypass Audit** | **CVE-2026-113373** | `CRITICAL 9.1` | Sonatype Nexus Repository 3 `3.86.0`–`3.97.1` (`< 3.98.0`) | [`plugins/nexus_repository/`](plugins/nexus_repository/) | `python plugins/nexus_repository/nexus_cve_2026_113373_audit.py <target>` |
| **NoMachine nxwebrunner Web Service Audit** | **CVE-2026-114549** | `CRITICAL 9.8` | NoMachine `nxwebrunner` `<= 9.7.3` | [`plugins/nomachine/`](plugins/nomachine/) | `python plugins/nomachine/nomachine_cve_2026_114549_audit.py <target>` |
| **Apache OFBiz Screen Descriptor & Login Key Audit** | **CVE-2026-83542** | `CRITICAL 9.8` | Apache OFBiz `< 24.09.08` | [`plugins/apache_ofbiz/`](plugins/apache_ofbiz/) | `python plugins/apache_ofbiz/apache_ofbiz_cve_2026_83542_audit.py <target>` |
| **Keycloak SAML HTTP-Redirect Signature Verification Audit** | **CVE-2026-117691** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.0` | [`plugins/keycloak/`](plugins/keycloak/) | `python plugins/keycloak/keycloak_cve_2026_117691_audit.py <target>` |
| **FreeSWITCH SIP & WebRTC Stack Version Audit** | **CVE-2026-116779** | `CRITICAL 9.8` | FreeSWITCH `< 1.11.3` | [`plugins/freeswitch/`](plugins/freeswitch/) | `python plugins/freeswitch/freeswitch_cve_2026_116779_audit.py <target>` |
| **WordPress Naimur Email OTP Verification Auth Bypass Audit** | **CVE-2026-104014** | `CRITICAL 9.8` | WordPress Naimur Email OTP Verification `<= 2.1.0` | [`plugins/wordpress/wp_naimur_email_otp/`](plugins/wordpress/wp_naimur_email_otp/) | `python plugins/wordpress/wp_naimur_email_otp/wp_naimur_email_otp_cve_2026_104014_audit.py <target>` |
| **WordPress Registration Form for WooCommerce PrivEsc Audit** | **CVE-2026-119075** | `CRITICAL 9.8` | WordPress Registration Form for WooCommerce `<= 1.1.4` | [`plugins/wordpress/wp_registration_form_woocommerce/`](plugins/wordpress/wp_registration_form_woocommerce/) | `python plugins/wordpress/wp_registration_form_woocommerce/wp_registration_form_woocommerce_cve_2026_119075_audit.py <target>` |
| **WordPress LatePoint Authentication Bypass Audit** | **CVE-2026-118066** | `CRITICAL 9.1` | WordPress LatePoint `<= 5.7.6` | [`plugins/wordpress/wp_latepoint/`](plugins/wordpress/wp_latepoint/) | `python plugins/wordpress/wp_latepoint/wp_latepoint_cve_2026_118066_audit.py <target>` |
| **WordPress Printcart Product Designer File Upload Audit** | **CVE-2026-19803** | `CRITICAL 9.8` | WordPress Printcart Product Designer `<= 2.13.2` | [`plugins/wordpress/wp_printcart_designer/`](plugins/wordpress/wp_printcart_designer/) | `python plugins/wordpress/wp_printcart_designer/wp_printcart_designer_cve_2026_19803_audit.py <target>` |
| **WordPress payever WooCommerce Gateway File Upload Audit** | **CVE-2026-93754** | `CRITICAL 9.8` | WordPress payever WooCommerce Gateway `<= 4.8.0` | [`plugins/wordpress/wp_payever_gateway/`](plugins/wordpress/wp_payever_gateway/) | `python plugins/wordpress/wp_payever_gateway/wp_payever_gateway_cve_2026_93754_audit.py <target>` |
| **OpenAM Live Session Token Disclosure & Auth Bypass Audit** | **CVE-2026-123551** | `CRITICAL 10.0` | OpenAM `< 16.1.4` (`14.0.0`–`16.1.3`) | [`plugins/openam/`](plugins/openam/) | `python plugins/openam/openam_cve_2026_123551_audit.py <target>` |
| **IBM API Connect Auth Bypass & RCE Audit** | **CVE-2026-17301** | `CRITICAL 9.8` | IBM API Connect `10.0.8.0`–`10.0.8.12`, `12.1.0.0`–`12.1.1.2` | [`plugins/ibm_api_connect/`](plugins/ibm_api_connect/) | `python plugins/ibm_api_connect/ibm_api_connect_cve_2026_17301_audit.py <target>` |
| **Keycloak Client Management JS Policy Upload RCE Audit** | **CVE-2026-120984** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.5` | [`plugins/keycloak_client_mgmt/`](plugins/keycloak_client_mgmt/) | `python plugins/keycloak_client_mgmt/keycloak_cve_2026_120984_audit.py <target>` |
| **WordPress Contact Form 7 File Upload Validation Audit** | **CVE-2026-114432** | `CRITICAL 9.8` | WordPress Contact Form 7 `< 6.2.4` | [`plugins/wordpress/wp_contact_form_7/`](plugins/wordpress/wp_contact_form_7/) | `python plugins/wordpress/wp_contact_form_7/wp_contact_form_7_cve_2026_114432_audit.py <target>` |
| **OpenEMR Multi-CVE Version Compliance Audit** | **CVE-2026-124445** | `CRITICAL 9.4` | OpenEMR `< 8.4.0` (`< 8.3.0`) | [`plugins/openemr/`](plugins/openemr/) | `python plugins/openemr/openemr_cve_2026_124445_audit.py <target>` |
| **imgproxy ICO Loader Version Compliance Audit** | **CVE-2026-123614** | `CRITICAL 9.3` | imgproxy `4.0.0`–`4.0.15` (`< 4.0.16`) | [`plugins/imgproxy/`](plugins/imgproxy/) | `python plugins/imgproxy/imgproxy_cve_2026_123614_audit.py <target>` |
| **SAP Web Dispatcher & NetWeaver Compliance Audit** | **CVE-2026-89126** | `CRITICAL 10.0` | SAP Web Dispatcher & ICM `7.22`–`9.21` | [`plugins/sap_netweaver/`](plugins/sap_netweaver/) | `python plugins/sap_netweaver/sap_netweaver_cve_2026_89126_audit.py <target>` |
| **Craft CMS Version Compliance Audit** | **CVE-2026-115934** | `CRITICAL 9.3` | Craft CMS `< 4.18.9` & `< 5.11.2` | [`plugins/craft_cms/`](plugins/craft_cms/) | `python plugins/craft_cms/craft_cms_cve_2026_115934_audit.py <target>` |
| **Redpanda Connect Version Compliance Audit** | **CVE-2026-123270** | `CRITICAL 9.8` | Redpanda Connect `4.39`–`4.110` (`< 4.111.0`) | [`plugins/redpanda_connect/`](plugins/redpanda_connect/) | `python plugins/redpanda_connect/redpanda_connect_cve_2026_123270_audit.py <target>` |
| **Fortinet FortiManager Version Compliance Audit** | **CVE-2026-126261** | `CRITICAL 9.8` | FortiManager `7.2.0`–`7.2.8`, `7.4.0`–`7.4.5`, `7.6.0`–`7.6.7`, `8.0.0` | [`plugins/fortimanager/`](plugins/fortimanager/) | `python plugins/fortimanager/fortimanager_cve_2026_126261_audit.py <target>` |
| **Ivanti Endpoint Manager Version Compliance Audit** | **CVE-2026-121653** | `CRITICAL 9.8` | Ivanti Endpoint Manager `< 2024 SU8` (`< 11.0.6.8`) | [`plugins/ivanti_epm/`](plugins/ivanti_epm/) | `python plugins/ivanti_epm/ivanti_epm_cve_2026_121653_audit.py <target>` |
| **Microsoft SharePoint Server Version Compliance Audit** | **CVE-2026-120002** | `CRITICAL 9.9` | SharePoint Server Subscription / 2019 / 2016 (Nov 2026 PU) | [`plugins/sharepoint/`](plugins/sharepoint/) | `python plugins/sharepoint/sharepoint_cve_2026_120002_audit.py <target>` |
| **Fortinet FortiOS Version Compliance Audit** | **CVE-2026-126259** | `CRITICAL 9.8` | FortiOS `7.0.0`–`7.0.19`, `7.2.0`–`7.2.13`, `7.4.0`–`7.4.12`, `7.6.0`–`7.6.7`, `8.0.0`–`8.0.1` | [`plugins/fortios/`](plugins/fortios/) | `python plugins/fortios/fortios_cve_2026_126259_audit.py <target>` |
| **Synology DiskStation Manager Version Compliance Audit** | **CVE-2026-76954** | `CRITICAL 9.8` | Synology DSM `< 7.2.1-69057-13`, `< 7.2.2-72806-10`, `< 7.3.2-86009-5`, `< 7.4.1-90080-1` | [`plugins/synology_dsm/`](plugins/synology_dsm/) | `python plugins/synology_dsm/synology_dsm_cve_2026_76954_audit.py <target>` |
| **Red Hat Quay Version Compliance Audit** | **CVE-2026-110697** | `CRITICAL 9.9` | Red Hat Quay `3.12`–`3.18` (`< 3.12.11` to `< 3.18.2`) | [`plugins/redhat_quay/`](plugins/redhat_quay/) | `python plugins/redhat_quay/redhat_quay_cve_2026_110697_audit.py <target>` |
| **GitLab CE/EE Version Compliance Audit** | **CVE-2026-110264** | `CRITICAL 10.0` | GitLab CE/EE `< 19.2.6`, `< 19.3.4`, `< 19.4.2` | [`plugins/gitlab/`](plugins/gitlab/) | `python plugins/gitlab/gitlab_cve_2026_110264_audit.py <target>` |
| **Citrix NetScaler Console & ADC Gateway Version Compliance Audit** | **CVE-2026-120869** | `CRITICAL 9.3` | NetScaler Console `< 14.1-66.58`, `< 13.1-62.29` | [`plugins/citrix_netscaler/`](plugins/citrix_netscaler/) | `python plugins/citrix_netscaler/citrix_netscaler_cve_2026_120869_audit.py <target>` |
| **WatchGuard Fireware OS & SonicWall SMA1000 Compliance Audit** | **CVE-2026-93866** | `CRITICAL 10.0` | Fireware OS `< 12.11.9` / `< 2026.2.1`, SonicWall SMA1000 `< 12.4.3-03312` | [`plugins/watchguard_fireware/`](plugins/watchguard_fireware/) | `python plugins/watchguard_fireware/watchguard_fireware_cve_2026_93866_audit.py <target>` |
| **Alinto SOGo Groupware SAML & Sieve Version Compliance Audit** | **CVE-2026-127131** | `CRITICAL 9.1` | Alinto SOGo `< 5.12.7` & `< 2.4.7` | [`plugins/sogo_groupware/`](plugins/sogo_groupware/) | `python plugins/sogo_groupware/sogo_cve_2026_127131_audit.py <target>` |

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
│   ├── wordpress/                         # Dedicated WordPress & WooCommerce plugins directory
│   │   ├── README.md                      # WordPress security plugins catalog
│   │   ├── wp_gravityforms/               # Gravity Forms PHP Object Injection (CVE-2026-103039)
│   │   ├── wp_naimur_email_otp/           # Naimur Email OTP Auth Bypass (CVE-2026-104014)
│   │   ├── wp_registration_form_woocommerce/ # Registration Form for WooCommerce PrivEsc (CVE-2026-119075)
│   │   ├── wp_latepoint/                  # LatePoint Authentication Bypass (CVE-2026-118066)
│   │   ├── wp_printcart_designer/         # Printcart Product Designer File Upload (CVE-2026-19803)
│   │   └── wp_payever_gateway/            # payever WooCommerce Gateway File Upload (CVE-2026-93754)
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
python plugins/wordpress/wp_gravityforms/wp_gravityforms_cve_2026_103039_audit.py 192.168.1.20 -p 80 443

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
