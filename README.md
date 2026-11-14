# RTMS Community Security Plugins & Fast-Response Auditors

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-RTMS_Suite-blue.svg)](https://3ts.ai)
[![Plugins](https://img.shields.io/badge/Plugins-57-brightgreen.svg)](CATALOG.md)
[![CVEs Covered](https://img.shields.io/badge/Critical_CVEs-117%2B-red.svg)](CATALOG.md)

Welcome to the official **RTMS Community Plugins** repository. This open-source hub currently provides **57 standalone security audit plugins** covering **117 critical CVEs** (`CVSS 9.0–10.0`), engineered for the **[RTMS Cybersecurity Suite](https://3ts.ai)** (Real-Time Monitoring & Security).

Each plugin is developed to provide rapid, reliable, and strictly non-destructive detection of critical emerging vulnerabilities (`CVSS >= 9.0`) across enterprise networks.

---

## 📚 Security Plugins Catalog (57 Plugins | 117 Critical CVEs)

> 💡 **Full Searchable Index:** Browse **[`CATALOG.md`](CATALOG.md)** for the single-page master table, or expand a domain below.

| Technology Domain | Modules | Representative Targets | Sub-Catalog / Reference |
|:---|:---:|:---|:---|
| **🛡️ Network, Firewalls & VPN Appliances** | `7` | Citrix NetScaler, FortiOS, FortiManager, WatchGuard, SonicWall, Barracuda, Synology DSM | [View in `CATALOG.md`](CATALOG.md#-1-network-appliances-firewalls--vpn-gateways) |
| **🔑 Identity, IAM, SSO & PKI** | `5` | Keycloak, OpenAM, IBM API Connect, eMudhra Weak CA | [View in `CATALOG.md`](CATALOG.md#-2-identity-iam-sso--pki-infrastructure) |
| **⚙️ Web Servers, Runtimes, DevOps & Containers** | `11` | FrankenPHP, PHP2Shell, GitLab, Red Hat Quay, Rancher, Nexus, pgAdmin 4, Redpanda, imgproxy, vsftpd, Chrome | [View in `CATALOG.md`](CATALOG.md#%EF%B8%8F-3-web-servers-runtimes-devops--containers) |
| **🏢 Enterprise Apps, ERP, ITSM & Healthcare** | `13` | SAP NetWeaver, SharePoint, OpenEMR, GLPI, ManageEngine, Ivanti EPM, Apache OFBiz, Craft CMS, SOGo, Payara, FreeSWITCH, NoMachine | [View in `CATALOG.md`](CATALOG.md#-4-enterprise-apps-erp-itsm-groupware--healthcare) |
| **🌐 WordPress & WooCommerce Ecosystem** | `21` | Gravity Forms, Contact Form 7, AutomatorWP Pro, ELEX HelpDesk, LatePoint, Elementor UAE, Descope, Streamit & 13 more | 👉 **[`plugins/wordpress/README.md`](plugins/wordpress/README.md)** |
| **📊 Total Public Repository** | **`57`** | **117 Critical CVEs Covered (`CVSS 9.0–10.0`)** | **[Full Master Index (`CATALOG.md`)](CATALOG.md)** |

<details>
<summary><b>🛡️ 1. Network Appliances, Firewalls & VPN Gateways (Click to expand — 7 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **Citrix NetScaler Console & ADC Gateway Audit** | **CVE-2026-120869** / **CVE-2026-120864** | `CRITICAL 9.5` | NetScaler ADC/Gateway `< 14.1-73.57`, `< 13.1-64.39` | [`plugins/citrix_netscaler/`](plugins/citrix_netscaler/) |
| **Fortinet FortiOS Version Compliance Audit** | **CVE-2026-126259** | `CRITICAL 9.8` | FortiOS `7.0.0`–`7.0.19`, `7.2.0`–`7.2.13`, `7.4.0`–`7.4.12`, `7.6.0`–`7.6.7`, `8.0.0`–`8.0.1` | [`plugins/fortios/`](plugins/fortios/) |
| **Fortinet FortiManager Version Compliance Audit** | **CVE-2026-126261** | `CRITICAL 9.8` | FortiManager `7.2.0`–`7.2.8`, `7.4.0`–`7.4.5`, `7.6.0`–`7.6.7`, `8.0.0` | [`plugins/fortimanager/`](plugins/fortimanager/) |
| **WatchGuard Fireware OS & SonicWall SMA1000 Audit** | **CVE-2026-93866** | `CRITICAL 10.0` | Fireware OS `< 12.11.9` / `< 2026.2.1`, SonicWall SMA1000 `< 12.4.3-03312` | [`plugins/watchguard_fireware/`](plugins/watchguard_fireware/) |
| **SonicWall GMS Internal File Read Audit** | **CVE-2026-109593** | `CRITICAL 9.1` | SonicWall Global Management System `<= 9.5.2` | [`plugins/sonicwall_gms/`](plugins/sonicwall_gms/) |
| **Barracuda Email Security Gateway Auth Bypass Audit** | **CVE-2026-116606** | `CRITICAL 9.3` | Barracuda Email Security Gateway `< 9.4.0.030` | [`plugins/barracuda_esg/`](plugins/barracuda_esg/) |
| **Synology DiskStation Manager Version Audit** | **CVE-2026-76954** | `CRITICAL 9.8` | Synology DSM `< 7.2.1-69057-13`, `< 7.2.2-72806-10`, `< 7.3.2-86009-5`, `< 7.4.1-90080-1` | [`plugins/synology_dsm/`](plugins/synology_dsm/) |

</details>

<details>
<summary><b>🔑 2. Identity, IAM, SSO & PKI Infrastructure (Click to expand — 5 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **OpenAM Live Session Token & Auth Bypass Audit** | **CVE-2026-123551** | `CRITICAL 10.0` | OpenAM `< 16.1.4` (`14.0.0`–`16.1.3`) | [`plugins/openam/`](plugins/openam/) |
| **Keycloak SAML HTTP-Redirect Signature Audit** | **CVE-2026-117691** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.0` | [`plugins/keycloak/`](plugins/keycloak/) |
| **Keycloak Client Management JS Policy RCE Audit** | **CVE-2026-120984** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.5` | [`plugins/keycloak_client_mgmt/`](plugins/keycloak_client_mgmt/) |
| **IBM API Connect Auth Bypass & RCE Audit** | **CVE-2026-17301** | `CRITICAL 9.8` | IBM API Connect `10.0.8.0`–`10.0.8.12`, `12.1.0.0`–`12.1.1.2` | [`plugins/ibm_api_connect/`](plugins/ibm_api_connect/) |
| **eMudhra Weak Intermediate CA Audit** | **CVE-2026-91403** | `CRITICAL 9.1` | WebPKI, Java JSSE, TLS endpoints | [`plugins/emudhra_weak_ca/`](plugins/emudhra_weak_ca/) |

</details>

<details>
<summary><b>⚙️ 3. Web Servers, Runtimes, DevOps & Containers (Click to expand — 11 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **FrankenPHP Application Server Compliance Audit** | **CVE-2026-128014** / **CVE-2026-128023** | `CRITICAL 9.3` | FrankenPHP `< 1.13.2` (`< 1.13.0`, `< 1.1.11`) | [`plugins/frankenphp/`](plugins/frankenphp/) |
| **PHP Core Stale Global State RCE Audit (PHP2Shell)** | **CVE-2026-109619** | `CRITICAL 9.2` | PHP 5.4 to 8.5.11, FastCGI, PAN-OS | [`plugins/php2shell/`](plugins/php2shell/) |
| **GitLab CE/EE Version Compliance Audit** | **CVE-2026-110264** | `CRITICAL 10.0` | GitLab CE/EE `< 19.2.6`, `< 19.3.4`, `< 19.4.2` | [`plugins/gitlab/`](plugins/gitlab/) |
| **Red Hat Quay Version Compliance Audit** | **CVE-2026-110697** | `CRITICAL 9.9` | Red Hat Quay `3.12`–`3.18` (`< 3.12.11` to `< 3.18.2`) | [`plugins/redhat_quay/`](plugins/redhat_quay/) |
| **SUSE Rancher Manager Meta-Proxy & Fleet Audit** | **CVE-2026-88811** | `CRITICAL 9.1` | SUSE Rancher `2.13`–`2.15` (`< 2.13.12`/`2.14.8`/`2.15.4`) | [`plugins/rancher/`](plugins/rancher/) |
| **Sonatype Nexus Repository 3 SAML/OIDC Bypass Audit** | **CVE-2026-113373** | `CRITICAL 9.1` | Sonatype Nexus Repository 3 `3.86.0`–`3.97.1` (`< 3.98.0`) | [`plugins/nexus_repository/`](plugins/nexus_repository/) |
| **pgAdmin 4 psql \copy RCE & Lockout Bypass Audit** | **CVE-2026-116241** | `CRITICAL 9.4` | pgAdmin 4 Server Mode `< 9.19` | [`plugins/pgadmin4/`](plugins/pgadmin4/) |
| **Redpanda Connect Version Compliance Audit** | **CVE-2026-123270** | `CRITICAL 9.8` | Redpanda Connect `4.39`–`4.110` (`< 4.111.0`) | [`plugins/redpanda_connect/`](plugins/redpanda_connect/) |
| **imgproxy ICO Loader Version Compliance Audit** | **CVE-2026-123614** | `CRITICAL 9.3` | imgproxy `4.0.0`–`4.0.15` (`< 4.0.16`) | [`plugins/imgproxy/`](plugins/imgproxy/) |
| **vsftpd FTPS Data Channel Hijacking Audit** | **CVE-2026-119568** | `CRITICAL 9.1` | vsftpd `<= 3.0.5` (Ubuntu, Debian, RHEL) | [`plugins/vsftpd/`](plugins/vsftpd/) |
| **Google Chrome & Headless Chromium Sandbox Audit** | **CVE-2026-126885** | `CRITICAL 9.6` | Google Chrome / Headless Chromium `< 157.0.8103.78` | [`plugins/google_chrome/`](plugins/google_chrome/) |

</details>

<details>
<summary><b>🏢 4. Enterprise Apps, ERP, ITSM, Groupware & Healthcare (Click to expand — 13 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **SAP Web Dispatcher & NetWeaver Compliance Audit** | **CVE-2026-89126** | `CRITICAL 10.0` | SAP Web Dispatcher & ICM `7.22`–`9.21` | [`plugins/sap_netweaver/`](plugins/sap_netweaver/) |
| **Microsoft SharePoint Server Version Compliance Audit** | **CVE-2026-120002** | `CRITICAL 9.9` | SharePoint Server Subscription / 2019 / 2016 (Nov 2026 PU) | [`plugins/sharepoint/`](plugins/sharepoint/) |
| **OpenEMR Multi-CVE Version Compliance Audit** | **CVE-2026-126473** / **CVE-2026-124445** | `CRITICAL 9.4` | OpenEMR `< 8.4.0` (`< 8.3.0`) | [`plugins/openemr/`](plugins/openemr/) |
| **GLPI Two-Factor Authentication Bypass Audit** | **CVE-2026-52848** | `CRITICAL 9.2` | GLPI `11.0.0` to `11.0.7` (`< 11.0.8`) | [`plugins/glpi/`](plugins/glpi/) |
| **Zoho ManageEngine ITSM, M365 Manager & DDI Audit** | **CVE-2026-12591** / **CVE-2026-12507** | `CRITICAL 9.9` | M365 Manager Plus `< 4818`, ServiceDesk Plus `< 15290`, DDI Central `< 6301` | [`plugins/manageengine_itsm/`](plugins/manageengine_itsm/) |
| **Zoho ManageEngine Log360 & EventLog Analyzer Audit** | **CVE-2026-13594** | `CRITICAL 9.1` | ManageEngine Log360 & EventLog Analyzer `<= 13062` | [`plugins/manageengine_log360/`](plugins/manageengine_log360/) |
| **Ivanti Endpoint Manager Version Compliance Audit** | **CVE-2026-121653** | `CRITICAL 9.8` | Ivanti Endpoint Manager `< 2024 SU8` (`< 11.0.6.8`) | [`plugins/ivanti_epm/`](plugins/ivanti_epm/) |
| **Apache OFBiz Screen Descriptor & Login Key Audit** | **CVE-2026-83542** | `CRITICAL 9.8` | Apache OFBiz `< 24.09.08` | [`plugins/apache_ofbiz/`](plugins/apache_ofbiz/) |
| **Craft CMS Version Compliance Audit** | **CVE-2026-115934** | `CRITICAL 9.3` | Craft CMS `< 4.18.9` & `< 5.11.2` | [`plugins/craft_cms/`](plugins/craft_cms/) |
| **Alinto SOGo Groupware SAML & Sieve Audit** | **CVE-2026-127131** | `CRITICAL 9.1` | Alinto SOGo `< 5.12.7` & `< 2.4.7` | [`plugins/sogo_groupware/`](plugins/sogo_groupware/) |
| **Azul Payara Server & Payara Micro Admin Auth Audit** | **CVE-2026-110003** / **CVE-2026-90908** | `CRITICAL 9.3` | Payara `< 7.6.0` / `< 7.2026.11`, `< 6.44.0`, `< 5.93.0` | [`plugins/azul_payara/`](plugins/azul_payara/) |
| **FreeSWITCH SIP & WebRTC Stack Version Audit** | **CVE-2026-116779** | `CRITICAL 9.8` | FreeSWITCH `< 1.11.3` | [`plugins/freeswitch/`](plugins/freeswitch/) |
| **NoMachine nxwebrunner Web Service Audit** | **CVE-2026-114549** | `CRITICAL 9.8` | NoMachine `nxwebrunner` `<= 9.7.3` | [`plugins/nomachine/`](plugins/nomachine/) |

</details>

---

## 🗂️ Repository Structure

```text
rtms-public/
├── LICENSE                                # MIT Open-Source License
├── README.md                              # Main overview & categorized plugin directory
├── CATALOG.md                             # Complete single-page master plugin catalog
├── CONTRIBUTING.md                        # Developer specification & AST security guardrails
├── pyproject.toml                         # Unified test & package configuration
├── requirements.txt                       # Consolidated Python dependencies
│
├── plugins/                               # Dedicated security plugins directory
│   ├── citrix_netscaler/                  # Citrix NetScaler Console & ADC/Gateway (10 CVEs)
│   ├── fortios/                           # Fortinet FortiOS compliance auditor
│   ├── frankenphp/                        # FrankenPHP Application Server compliance auditor
│   ├── openemr/                           # OpenEMR healthcare EHR compliance auditor (6 CVEs)
│   ├── wordpress/                         # Dedicated WordPress & WooCommerce plugins hub (21 plugins)
│   │   ├── README.md                      # WordPress security plugins catalog
│   │   └── wp_*/                          # Individual WordPress plugin auditors
│   └── ...                                # 36 enterprise & infrastructure plugin directories
│
└── tests/                                 # Automated unit test suite (321 tests)
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

```bash
# Audit Citrix NetScaler Console / ADC & Gateway appliances
python plugins/citrix_netscaler/citrix_netscaler_cve_2026_120869_audit.py 192.168.1.10 -p 443 8443

# Audit FrankenPHP Application Server instances
python plugins/frankenphp/frankenphp_cve_2026_128014_audit.py 192.168.1.20 -p 80 443 8080

# Audit OpenEMR healthcare installations
python plugins/openemr/openemr_cve_2026_124445_audit.py 192.168.1.30 -p 80 443

# Audit a WordPress installation for a specific plugin
python plugins/wordpress/wp_automatorwp_pro/wp_automatorwp_pro_cve_2026_126173_audit.py 192.168.1.40 -p 80 443
```

---

## 🔌 Integration with RTMS Cybersecurity Suite

1. **File Drop into RTMS Scanner Probe**: Copy desired plugin scripts into `/opt/rtms-scanner/external_plugins/`. The dynamic RTMS plugin loader automatically validates the AST security guardrails and activates the plugin.
2. **Upload via RTMS Web UI**: Navigate to **Administration > Plugins** in the RTMS Web Console and upload the Python plugin file for automated subnet discovery or surgical IP verification.

---

## 🛠️ Contributing a New Plugin

Please read our full **[`CONTRIBUTING.md`](CONTRIBUTING.md)** for detailed specifications, AST security guardrails (`BasePlugin` contract, read-only network operations), and unit test guidelines:

```bash
uv run --extra dev pytest
```

---

## 🛡️ About RTMS (Real-Time Monitoring & Security)

Published with ❤️ by **[3TS Consulting SRL](https://3ts.ai)**, the team behind **RTMS** — a sovereign European cybersecurity and network posture management platform engineered for continuous asset visibility, threat detection, and **NIS 2 / CRA** regulatory compliance.

* 🌐 **Website:** [https://3ts.ai](https://3ts.ai)
* 📧 **Contact:** [contact@3ts.ai](mailto:contact@3ts.ai)
* ⚖️ **License:** Distributed under the **MIT License** (see [`LICENSE`](LICENSE)).
