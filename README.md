# RTMS Community Security Plugins & Fast-Response Auditors

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-RTMS_Suite-blue.svg)](https://3ts.ai)
[![Plugins](https://img.shields.io/badge/Plugins-160-brightgreen.svg)](CATALOG.md)
[![CVEs Covered](https://img.shields.io/badge/Critical_CVEs-350%2B-red.svg)](CATALOG.md)

Welcome to the official **RTMS Community Plugins** repository. This open-source hub currently provides **160 standalone security audit plugins** covering **350 critical CVEs** (`CVSS 9.0–10.0`), engineered for the **[RTMS Cybersecurity Suite](https://3ts.ai)** (Real-Time Monitoring & Security).

Each plugin is developed to provide rapid, reliable, and strictly non-destructive detection of critical emerging vulnerabilities (`CVSS >= 9.0`) across enterprise networks.

---

## 📚 Security Plugins Catalog (160 Plugins | 350 Critical CVEs)

> 💡 **Full Searchable Index:** Browse **[`CATALOG.md`](CATALOG.md)** for the single-page master table, or expand a domain below.

| Technology Domain | Modules | Representative Targets | Sub-Catalog / Reference |
|:---|:---:|:---|:---|
| **🛡️ Network, Firewalls & VPN Appliances** | `14` | TRENDnet TEW, SEPPmail, HPE ArubaOS, HPE Aruba AirWave, FortiMail, FortiAnalyzer, F5 BIG-IP, Citrix NetScaler, FortiOS, FortiManager, WatchGuard, SonicWall, Barracuda, Synology DSM | [View in `CATALOG.md`](CATALOG.md#-1-network-appliances-firewalls--vpn-gateways) |
| **🔑 Identity, IAM, SSO & PKI** | `9` | Mendix OIDC Provider, Direk Tech Smart Portal, Oracle Access Manager (OAM), Keycloak, OpenAM, IBM API Connect, Cyrus SASL, eMudhra Weak CA | [View in `CATALOG.md`](CATALOG.md#-2-identity-iam-sso--pki-infrastructure) |
| **⚙️ Web Servers, Runtimes, DevOps & Containers** | `46` | Google Cloud (GKE Fleet / Vertex AI / App Integration), Canonical LXD & pylxd, Coder, Pulp `pulp_python`, `llama.cpp`, Eclipse Ditto, Parse Server, HKUDS `nanobot`, LaraDashboard, Oracle Database, Azure DevOps Server, Eclipse Mosquitto, Xen Orchestra, ArangoDB, Camunda 8, Webmin, Wing FTP Server, Rclone, Jenkins, Mozilla Firefox & Thunderbird, FFmpeg, Cribl Stream, Fastify, SurrealDB, Apache Tomcat, PEM, PHP-FPM, NGINX, TeamCity, MySQL, WebLogic, TomEE, AdminNeo, Arize Phoenix, FrankenPHP, Dokploy, GitLab, Red Hat Quay, Rancher, Nexus, pgAdmin 4, Chrome | [View in `CATALOG.md`](CATALOG.md#%EF%B8%8F-3-web-servers-runtimes-devops--containers) |
| **🏢 Enterprise Apps, ERP, ITSM & Healthcare** | `40` | Drupal Core, MONEO ERP, POSTAL 2, VMware ESXi, RealVNC Server, Mitel OpenScape 4000, Budibase, ToolJet, Frappe Framework, Twenty CRM, SiYuan, Adobe AEM, Adobe Campaign, Oracle EBS & APEX, TYPO3 CMS, mailcow, FleetDM, N-able N-central, NocoDB, SolarWinds Serv-U, Joomla!, MediaWiki, Poste.io, Splunk, VMware vCenter, OpenCTI, phpMyFAQ, SAP NetWeaver, SharePoint, OpenEMR, GLPI, ManageEngine, Ivanti EPM, OFBiz, Craft CMS, SOGo, Payara, FreeSWITCH, NoMachine | [View in `CATALOG.md`](CATALOG.md#-4-enterprise-apps-erp-itsm-groupware--healthcare) |
| **🌐 WordPress & WooCommerce Ecosystem** | `51` | WPMasterToolKit, MemberPress Discord Addon, Revertix, WebinarIgnition, Hello Clever Gateway, Media Library Assistant, Amelia, Ultimate Member, FunnelKit Automations, Simple Membership, WordPress File Upload, WP Job Portal, Sneeit Framework, WP Rocket, Simple Shopping Cart, Nexter Blocks Pro, miniOrange OTP Verification, Tribulant Newsletters, WP Duplicate, WP Photo Album Plus, Custom Block Builder, Auth Armor, Gravity Forms, Contact Form 7 & 27 more | 👉 **[`plugins/wordpress/README.md`](plugins/wordpress/README.md)** |
| **📊 Total Public Repository** | **`160`** | **350 Critical CVEs Covered (`CVSS 9.0–10.0`)** | **[Full Master Index (`CATALOG.md`)](CATALOG.md)** |

<details>
<summary><b>🛡️ 1. Network Appliances, Firewalls & VPN Gateways (Click to expand — 14 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **TRENDnet TEW-751DR & TEW-733GR UPnP Firmware Compliance Audit** | **CVE-2026-138004** / **CVE-2026-138003** | `CRITICAL 9.3` | TRENDnet TEW-751DR & TEW-733GR `<= 1.03B01` (2 CVEs) | [`plugins/trendnet_tew/`](plugins/trendnet_tew/) |
| **SEPPmail Secure E-Mail Gateway Pre-Auth SSTI & GINA Audit** | **CVE-2026-130637** / **CVE-2026-124843** | `CRITICAL 9.3` | SEPPmail Secure E-Mail Gateway `< 15.1.2` (3 CVEs) | [`plugins/seppmail/`](plugins/seppmail/) |
| **HPE ArubaOS Wireless Controller & Gateway RCE Audit** | **CVE-2026-95787** | `CRITICAL 10.0` | HPE ArubaOS `10.4.0.0`–`10.4.1.13`, `10.7.0.0`–`10.7.2.6`, `10.8.0.0`–`10.8.1.1` | [`plugins/hpe_arubaos/`](plugins/hpe_arubaos/) |
| **Fortinet FortiMail Heap Overflow RCE Compliance Audit** | **CVE-2026-126263** | `CRITICAL 9.8` | FortiMail `7.4.0`–`7.4.6`, `7.6.0`–`7.6.4`, `8.0.0`–`8.0.1` | [`plugins/fortimail/`](plugins/fortimail/) |
| **Fortinet FortiAnalyzer Authorization Bypass Audit** | **CVE-2026-126229** | `CRITICAL 9.1` | FortiAnalyzer `7.2.0`–`7.2.12`, `7.4.0`–`7.4.11`, `7.6.0`–`7.6.7`, `8.0.0`–`8.0.1` | [`plugins/fortianalyzer/`](plugins/fortianalyzer/) |
| **HPE Aruba AirWave Management Platform Compliance Audit** | **CVE-2026-133973** / **CVE-2026-133971** | `CRITICAL 9.8` | HPE Networking Management Software (AirWave) `8.3.0.0`–`8.3.0.7` (`< 8.3.0.8`) (3 CVEs) | [`plugins/hpe_airwave/`](plugins/hpe_airwave/) |
| **F5 BIG-IP TMOS & APM Version Compliance Audit** | **CVE-2026-123637** | `CRITICAL 9.3` | F5 BIG-IP `17.1.x < 17.1.3.6`, `17.5.x < 17.5.1.10`, `21.1.x < 21.1.0.2` (7 CVEs) | [`plugins/f5_bigip/`](plugins/f5_bigip/) |
| **Citrix NetScaler Console & ADC Gateway Audit** | **CVE-2026-120869** / **CVE-2026-120864** | `CRITICAL 9.5` | NetScaler ADC/Gateway `< 14.1-73.57`, `< 13.1-64.39` | [`plugins/citrix_netscaler/`](plugins/citrix_netscaler/) |
| **Fortinet FortiOS Version Compliance Audit** | **CVE-2026-126259** | `CRITICAL 9.8` | FortiOS `7.0.0`–`7.0.19`, `7.2.0`–`7.2.13`, `7.4.0`–`7.4.12`, `7.6.0`–`7.6.7`, `8.0.0`–`8.0.1` | [`plugins/fortios/`](plugins/fortios/) |
| **Fortinet FortiManager Version Compliance Audit** | **CVE-2026-126261** | `CRITICAL 9.8` | FortiManager `7.2.0`–`7.2.8`, `7.4.0`–`7.4.5`, `7.6.0`–`7.6.7`, `8.0.0` | [`plugins/fortimanager/`](plugins/fortimanager/) |
| **WatchGuard Fireware OS & SonicWall SMA1000 Audit** | **CVE-2026-93866** | `CRITICAL 10.0` | Fireware OS `< 12.11.9` / `< 2026.2.1`, SonicWall SMA1000 `< 12.4.3-03312` | [`plugins/watchguard_fireware/`](plugins/watchguard_fireware/) |
| **SonicWall GMS Internal File Read Audit** | **CVE-2026-109593** | `CRITICAL 9.1` | SonicWall Global Management System `<= 9.5.2` | [`plugins/sonicwall_gms/`](plugins/sonicwall_gms/) |
| **Barracuda Email Security Gateway Auth Bypass Audit** | **CVE-2026-116606** | `CRITICAL 9.3` | Barracuda Email Security Gateway `< 9.4.0.030` | [`plugins/barracuda_esg/`](plugins/barracuda_esg/) |
| **Synology DiskStation Manager Version Audit** | **CVE-2026-120382** / **CVE-2026-76954** | `CRITICAL 9.8` | Synology DSM `< 7.1.1-42962-10`, `< 7.2.1-69057-14`, `< 7.2.2-72806-11`, `< 7.3.2-86009-6`, `< 7.4.1-90080-2` | [`plugins/synology_dsm/`](plugins/synology_dsm/) |

</details>

<details>
<summary><b>🔑 2. Identity, IAM, SSO & PKI Infrastructure (Click to expand — 9 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **Mendix OIDC Provider JWT Integrity Validation Bypass Audit** | **CVE-2026-124981** | `CRITICAL 9.4` | Mendix OIDC Provider `< V4.3.0` (Mendix 9), `< V6.0.0` (Mendix 10/11) | [`plugins/mendix_oidc/`](plugins/mendix_oidc/) |
| **Direk Tech Smart Portal AD Domain Admins Authorization Audit** | **CVE-2026-137706** | `CRITICAL 9.4` | Direk Tech Smart Portal `< 2026.12.0` | [`plugins/direk_smart_portal/`](plugins/direk_smart_portal/) |
| **Oracle Access Manager (OAM) SSO Engine Compliance Audit** | **CVE-2026-91510** | `CRITICAL 10.0` | Oracle Access Manager `12.2.1.4.0`, `14.1.2.1.0` | [`plugins/oracle_access_manager/`](plugins/oracle_access_manager/) |
| **OpenAM Live Session Token & Auth Bypass Audit** | **CVE-2026-123551** | `CRITICAL 10.0` | OpenAM `< 16.1.4` (`14.0.0`–`16.1.3`) | [`plugins/openam/`](plugins/openam/) |
| **Keycloak SAML HTTP-Redirect Signature Audit** | **CVE-2026-117691** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.0` | [`plugins/keycloak/`](plugins/keycloak/) |
| **Keycloak Client Management JS Policy RCE Audit** | **CVE-2026-120984** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.5` | [`plugins/keycloak_client_mgmt/`](plugins/keycloak_client_mgmt/) |
| **IBM API Connect Auth Bypass & RCE Audit** | **CVE-2026-17301** / **CVE-2026-17410** | `CRITICAL 9.9` | IBM API Connect `10.0.8.0`–`10.0.8.12`, `12.1.0.0`–`12.1.1.2` | [`plugins/ibm_api_connect/`](plugins/ibm_api_connect/) |
| **eMudhra Weak Intermediate CA Audit** | **CVE-2026-91403** | `CRITICAL 9.1` | WebPKI, Java JSSE, TLS endpoints | [`plugins/emudhra_weak_ca/`](plugins/emudhra_weak_ca/) |
| **Cyrus SASL SRP Authentication Bypass Audit** | **CVE-2026-129483** | `CRITICAL 9.3` | Cyrus SASL (`libsasl2`) `<= 2.1.28` | [`plugins/cyrus_sasl/`](plugins/cyrus_sasl/) |

</details>

<details>
<summary><b>⚙️ 3. Web Servers, Runtimes, DevOps & Containers (Click to expand — 46 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **Google Cloud Managed Services Revision Compliance Audit** | **CVE-2026-106169** / **CVE-2026-85258** / **CVE-2026-110739** | `CRITICAL 9.4` | GCP Application Integration `< 2026-09-22`, Vertex AI `< 2026-04-13`, GKE Fleet `< 2026-09-25` (3 CVEs) | [`plugins/gcp_managed_services/`](plugins/gcp_managed_services/) |
| **Canonical LXD OIDC Auth Bypass & pylxd TLS Validation Audit** | **CVE-2026-135384** / **CVE-2026-127163** | `CRITICAL 9.2` | Canonical LXD `< 5.0.12`, `< 5.21.10`, `< 6.10.2` & `pylxd < 2.4.3` (2 CVEs) | [`plugins/canonical_lxd/`](plugins/canonical_lxd/) |
| **Coder AWS IAM Database Password Disclosure Audit** | **CVE-2026-137547** | `CRITICAL 9.2` | Coder `< 2.29.27`, `< 2.34.19`, `< 2.37.11`, `< 2.38.7`, `< 2.39.1` | [`plugins/coder/`](plugins/coder/) |
| **Pulp `pulp_python` Pull-Through Caching SSRF Audit** | **CVE-2026-126984** | `CRITICAL 10.0` | `pulp_python` `3.6 < 3.11.10`, `3.12 < 3.12.11`, `3.13 < 3.13.9`, `3.14 < 3.19.8`, `3.20 < 3.27.10`, `3.28 < 3.36.7`, `3.37 < 3.38.2` | [`plugins/pulp_python/`](plugins/pulp_python/) |
| **`llama.cpp` ggml RPC Server Heap Out-of-Bounds Write Audit** | **CVE-2026-137567** | `CRITICAL 9.3` | `llama.cpp` `b11450` to `< b12658` | [`plugins/llama_cpp/`](plugins/llama_cpp/) |
| **Eclipse Ditto Mozilla Rhino Sandbox Escape Audit** | **CVE-2026-135203** | `CRITICAL 9.4` | Eclipse Ditto `0.3.0-M1`–`3.8.15` (`< 3.8.16`), `3.9.0`–`3.9.9` (`< 3.9.10`) | [`plugins/eclipse_ditto/`](plugins/eclipse_ditto/) |
| **Parse Server Google Play Games Auth Bypass Audit** | **CVE-2026-137465** | `CRITICAL 9.1` | Parse Server `3.10.0`–`< 8.6.123`, `9.0.0`–`< 9.11.1-alpha.4` | [`plugins/parse_server/`](plugins/parse_server/) |
| **HKUDS `nanobot` TLS Certificate Validation Bypass Audit** | **CVE-2026-137463** | `CRITICAL 9.1` | HKUDS `nanobot` `0.1.4` to `< 0.4.1` | [`plugins/hkuds_nanobot/`](plugins/hkuds_nanobot/) |
| **LaraDashboard Module Namespace Path Traversal Audit** | **CVE-2026-137544** | `CRITICAL 9.4` | LaraDashboard `< 1.5.0` | [`plugins/laradashboard/`](plugins/laradashboard/) |
| **Oracle Database Server (DBMS_AQ / AQAdm) Compliance Audit** | **CVE-2026-114848** | `CRITICAL 9.9` | Oracle Database `19.3`–`19.33`, `21.3`–`21.24`, `23.4.0`–`23.26.3` | [`plugins/oracle_database/`](plugins/oracle_database/) |
| **Microsoft Azure DevOps Server 2025 RCE Compliance Audit** | **CVE-2026-109467** | `CRITICAL 9.9` | Azure DevOps Server 2025 `< Patch 9` | [`plugins/azure_devops_server/`](plugins/azure_devops_server/) |
| **Eclipse Mosquitto MQTT Broker Auth Bypass & RCE Audit** | **CVE-2026-110486** | `CRITICAL 9.8` | Eclipse Mosquitto `2.1.0`–`2.1.2` (`< 2.1.3`) | [`plugins/eclipse_mosquitto/`](plugins/eclipse_mosquitto/) |
| **Xen Orchestra & xo-server API Command Injection Audit** | **CVE-2026-133469** | `CRITICAL 9.8` | Xen Orchestra `< 6.9.2`, `6.10.0` & `xo-server` `< 5.211.2`, `5.213.0` | [`plugins/xen_orchestra/`](plugins/xen_orchestra/) |
| **ArangoDB Foxx Microservice Sandbox Escape Audit** | **CVE-2026-126755** | `CRITICAL 9.3` | ArangoDB `< 3.12.11` | [`plugins/arangodb/`](plugins/arangodb/) |
| **Camunda 8 Persistent Web Session Deserialization Audit** | **CVE-2026-77230** | `CRITICAL 9.2` | Camunda `8.8 < 8.8.47`, `8.9 < 8.9.29`, `8.10 < 8.10.10`, `8.11.0-alpha1` | [`plugins/camunda/`](plugins/camunda/) |
| **Webmin Insecure Default Admin Provisioning Audit** | **CVE-2026-134639** | `CRITICAL 9.2` | Webmin `<= 2.670` (`< 2.671`) | [`plugins/webmin/`](plugins/webmin/) |
| **Wing FTP Server Predictable Admin Session Token Audit** | **CVE-2026-135171** | `CRITICAL 9.2` | Wing FTP Server `< 8.2.8` (`<= 8.2.7`) | [`plugins/wing_ftp_server/`](plugins/wing_ftp_server/) |
| **Rclone `serve sftp --auth-proxy` Auth Bypass Audit** | **CVE-2026-134352** | `CRITICAL 9.2` | Rclone `1.51.0`–`1.75.x` (`< 1.76.0`) | [`plugins/rclone/`](plugins/rclone/) |
| **Jenkins Script Security Plugin Sandbox Bypass Audit** | **CVE-2026-136835** | `CRITICAL 9.9` | Jenkins Script Security Plugin (`script-security`) `<= 1436.v1082791135e4` | [`plugins/jenkins/`](plugins/jenkins/) |
| **Mozilla Firefox, Firefox ESR & Thunderbird Sandbox Audit** | **CVE-2026-135597** | `CRITICAL 9.6` | Firefox / Thunderbird `< 161.0`, ESR `< 153.8`, ESR `< 115.46` (18 CVEs) | [`plugins/mozilla_firefox/`](plugins/mozilla_firefox/) |
| **FFmpeg libavfilter Heap Out-of-Bounds Compliance Audit** | **CVE-2026-135736** / **CVE-2026-135743** | `CRITICAL 9.2` | FFmpeg `4.3` / `4.4` to `< 9.1` | [`plugins/ffmpeg/`](plugins/ffmpeg/) |
| **Cribl Stream REST Collector Pagination Compliance Audit** | **CVE-2026-115899** | `CRITICAL 9.3` | Cribl Stream `<= 4.20.4` (`< 4.20.5`) | [`plugins/cribl_stream/`](plugins/cribl_stream/) |
| **Fastify Middleware (`@fastify/express` & `@fastify/middie`) Audit** | **CVE-2026-135279** / **CVE-2026-133120** | `CRITICAL 9.1` | `@fastify/express < 4.0.14`, `@fastify/middie <= 9.3.7` (6 CVEs) | [`plugins/fastify/`](plugins/fastify/) |
| **SurrealDB Embedded JS Capability Bypass Audit** | **CVE-2026-134292** | `CRITICAL 9.3` | SurrealDB `>= 1.0.0, < 4.0.0` | [`plugins/surrealdb/`](plugins/surrealdb/) |
| **Apache Tomcat Multi-CVE Version Compliance Audit** | **CVE-2026-133325** | `CRITICAL 9.8` | Apache Tomcat `< 11.0.30`, `< 10.1.63`, `< 9.0.125`, EOL `<= 8.5.100` (4 CVEs) | [`plugins/apache_tomcat/`](plugins/apache_tomcat/) |
| **Postgres Enterprise Manager (PEM) Multi-CVE Audit** | **CVE-2026-132660** | `CRITICAL 9.4` | EDB Postgres Enterprise Manager (PEM) `< 10.6.1` (3 CVEs) | [`plugins/postgres_enterprise_manager/`](plugins/postgres_enterprise_manager/) |
| **PHP & PHP-FPM Multi-CVE Version Compliance Audit** | **CVE-2026-129289** | `CRITICAL 9.2` | PHP / PHP-FPM `8.2 < 8.2.36`, `8.3 < 8.3.37`, `8.4 < 8.4.28`, `8.5 < 8.5.13` (7 CVEs) | [`plugins/php_fpm/`](plugins/php_fpm/) |
| **NGINX Open Source & NGINX Plus Version Compliance Audit** | **CVE-2026-121810** | `CRITICAL 9.2` | NGINX Open Source `< 1.30.7`, `1.31.0`–`1.31.8` (`< 1.31.9`) & NGINX Plus (5 CVEs) | [`plugins/nginx/`](plugins/nginx/) |
| **JetBrains TeamCity Version Compliance Audit** | **CVE-2026-132234** / **CVE-2026-132891** | `CRITICAL 9.9` | JetBrains TeamCity `< 2025.11.8` & `2026.1.0`–`2026.1.3` (`< 2026.1.4`) (5 CVEs) | [`plugins/jetbrains_teamcity/`](plugins/jetbrains_teamcity/) |
| **Oracle MySQL Server & Cluster Compliance Audit** | **CVE-2026-114952** | `CRITICAL 9.1` | MySQL Server `8.4.0`–`8.4.13`, `9.7.0`–`9.7.4`, `26.10` & Cluster `8.0.0`–`8.0.50` | [`plugins/mysql/`](plugins/mysql/) |
| **Oracle WebLogic Server Version Compliance Audit** | **CVE-2026-91569** | `CRITICAL 10.0` | Oracle WebLogic Server `12.2.1.4.0`, `14.1.1.0.0`, `14.1.2.0.0`, `15.1.1.0.0` (7 CVEs) | [`plugins/oracle_weblogic/`](plugins/oracle_weblogic/) |
| **Apache TomEE & OpenEJB Version Compliance Audit** | **CVE-2026-87756** | `CRITICAL 9.8` | Apache TomEE / OpenEJB `< 10.3.0`, `11.0.0-M1` (9 CVEs) | [`plugins/apache_tomee/`](plugins/apache_tomee/) |
| **AdminNeo Database Manager Compliance Audit** | **CVE-2026-130366** / **CVE-2026-130380** | `CRITICAL 9.2` | AdminNeo `< 5.9.1` | [`plugins/adminneo/`](plugins/adminneo/) |
| **Arize AI Phoenix Version Compliance Audit** | **CVE-2026-53998** | `CRITICAL 10.0` | Arize AI Phoenix `>= 13.0.0, < 15.7.0` | [`plugins/arize_phoenix/`](plugins/arize_phoenix/) |
| **FrankenPHP Application Server Compliance Audit** | **CVE-2026-128014** / **CVE-2026-128023** | `CRITICAL 9.3` | FrankenPHP `< 1.13.2` (`< 1.13.0`, `< 1.1.11`) | [`plugins/frankenphp/`](plugins/frankenphp/) |
| **Dokploy PaaS Version Compliance Audit** | **CVE-2026-129433** | `CRITICAL 9.4` | Dokploy `< 0.31.1` (`<= 0.31.0`) | [`plugins/dokploy/`](plugins/dokploy/) |
| **PHP Core Stale Global State RCE Audit (PHP2Shell)** | **CVE-2026-109619** | `CRITICAL 9.2` | PHP 5.4 to 8.5.11, FastCGI, PAN-OS | [`plugins/php2shell/`](plugins/php2shell/) |
| **GitLab CE/EE Version Compliance Audit** | **CVE-2026-110264** | `CRITICAL 10.0` | GitLab CE/EE `< 19.2.6`, `< 19.3.4`, `< 19.4.2` | [`plugins/gitlab/`](plugins/gitlab/) |
| **Red Hat Quay Version Compliance Audit** | **CVE-2026-110697** | `CRITICAL 9.9` | Red Hat Quay `3.12`–`3.18` (`< 3.12.11` to `< 3.18.2`) | [`plugins/redhat_quay/`](plugins/redhat_quay/) |
| **SUSE Rancher Manager Meta-Proxy & Fleet Audit** | **CVE-2026-88811** | `CRITICAL 9.1` | SUSE Rancher `2.13`–`2.15` (`< 2.13.12`/`2.14.8`/`2.15.4`) | [`plugins/rancher/`](plugins/rancher/) |
| **Sonatype Nexus Repository 3 SAML/OIDC Bypass Audit** | **CVE-2026-113373** | `CRITICAL 9.1` | Sonatype Nexus Repository 3 `3.86.0`–`3.97.1` (`< 3.98.0`) | [`plugins/nexus_repository/`](plugins/nexus_repository/) |
| **pgAdmin 4 psql \copy RCE & Lockout Bypass Audit** | **CVE-2026-116241** | `CRITICAL 9.4` | pgAdmin 4 Server Mode `< 9.19` | [`plugins/pgadmin4/`](plugins/pgadmin4/) |
| **Redpanda Connect Version Compliance Audit** | **CVE-2026-123270** | `CRITICAL 9.8` | Redpanda Connect `4.39`–`4.110` (`< 4.111.0`) | [`plugins/redpanda_connect/`](plugins/redpanda_connect/) |
| **imgproxy ICO Loader Version Compliance Audit** | **CVE-2026-123614** | `CRITICAL 9.3` | imgproxy `4.0.0`–`4.0.15` (`< 4.0.16`) | [`plugins/imgproxy/`](plugins/imgproxy/) |
| **vsftpd FTPS Data Channel Hijacking Audit** | **CVE-2026-119568** | `CRITICAL 9.1` | vsftpd `<= 3.0.5` (Ubuntu, Debian, RHEL) | [`plugins/vsftpd/`](plugins/vsftpd/) |
| **Google Chrome & Headless Chromium Sandbox Audit** | **CVE-2026-134401** / **CVE-2026-131088** / **CVE-2026-126885** | `CRITICAL 9.6` | Google Chrome / Headless Chromium `< 158.0.8127.88` (19 CVEs) | [`plugins/google_chrome/`](plugins/google_chrome/) |

</details>

<details>
<summary><b>🏢 4. Enterprise Apps, ERP, ITSM, Groupware & Healthcare (Click to expand — 40 plugins)</b></summary>

<br>

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory |
|:---|:---:|:---:|:---|:---:|
| **Drupal Core Access Control & Forceful Browsing Audit** | **CVE-2026-136716** / **CVE-2026-132165** | `CRITICAL 9.8` | Drupal Core `<= 10.6.23`, `11.0.0`–`11.3.23`, `11.4.0`–`11.4.14` (2 CVEs) | [`plugins/drupal/`](plugins/drupal/) |
| **MONEO ERP WebSocket JSON-RPC Session Bypass Audit** | **CVE-2026-59103** | `CRITICAL 9.3` | MONEO ERP `< 2026.11.28` | [`plugins/moneo_erp/`](plugins/moneo_erp/) |
| **POSTAL 2 Workshop Mod Sandbox Escape Build Audit** | **CVE-2026-138154** | `CRITICAL 9.3` | POSTAL 2 `< build 26810491` | [`plugins/postal2/`](plugins/postal2/) |
| **VMware ESX / ESXi I/O Filter & XHCI USB Controller Audit** | **CVE-2026-123910** / **CVE-2026-123911** | `CRITICAL 9.8` | VMware ESXi `9.1 < 9.1.2.0`, `9.0 < 9.0.2.0200`, `8.0 < 8.0 U3m`, VCF `5.x < 5.2.5` (3 CVEs) | [`plugins/vmware_esxi/`](plugins/vmware_esxi/) |
| **RealVNC Server Unauthenticated UDP RCE Compliance Audit** | **CVE-2026-137738** | `CRITICAL 9.8` | RealVNC Server `6.4.0`–`7.19.0` (`< 7.19.1`) | [`plugins/realvnc_server/`](plugins/realvnc_server/) |
| **Mitel OpenScape 4000 & Manager Command Injection & Auth Audit** | **CVE-2026-137721** / **CVE-2026-137724** | `CRITICAL 10.0` | Mitel OpenScape 4000 & Manager `V10 <= R1.68`, `V11 R0.22`–`R2.11` (3 CVEs) | [`plugins/mitel_openscape/`](plugins/mitel_openscape/) |
| **Budibase Server Prototype Pollution & OIDC/SSO Auth Bypass Audit** | **CVE-2026-137498** / **CVE-2026-137499** | `CRITICAL 9.9` | Budibase `3.39.18`–`< 4.0.0` (2 CVEs) | [`plugins/budibase/`](plugins/budibase/) |
| **ToolJet OAuth SSO & Release Workflow Compliance Audit** | **CVE-2026-137536** / **CVE-2026-137964** | `CRITICAL 9.3` | ToolJet `< 3.21.96-LTS` (`< 3.21.94-beta`) (2 CVEs) | [`plugins/tooljet/`](plugins/tooljet/) |
| **Frappe Framework Document.update() Authorization Audit** | **CVE-2026-137550** | `CRITICAL 9.3` | Frappe Framework `< 15.122.0`, `16.x < 16.50.0` | [`plugins/frappe/`](plugins/frappe/) |
| **Twenty CRM Multi-Workspace Invitation Auth Bypass Audit** | **CVE-2026-137584** | `CRITICAL 9.1` | Twenty CRM `<= 2.63.0` (`< 2.63.1`) | [`plugins/twenty_crm/`](plugins/twenty_crm/) |
| **SiYuan WebDAV Error Rendering XSS Compliance Audit** | **CVE-2026-137471** | `CRITICAL 9.0` | SiYuan `< 3.8.10` | [`plugins/siyuan/`](plugins/siyuan/) |
| **Adobe Experience Manager (AEM) Forms & Core RCE Audit** | **CVE-2026-132877** / **CVE-2026-123266** | `CRITICAL 9.9` | Adobe Experience Manager `6.5 <= 6.5.26.0` (2 CVEs) | [`plugins/adobe_aem/`](plugins/adobe_aem/) |
| **Adobe Campaign Classic Multi-CVE RCE & SQLi Audit** | **CVE-2026-125675** / **CVE-2026-123987** | `CRITICAL 9.9` | Adobe Campaign Classic `<= 7.4.4 build 9403`, `7.4.5 <= build 9420` (11 CVEs) | [`plugins/adobe_campaign/`](plugins/adobe_campaign/) |
| **Oracle E-Business Suite & Oracle APEX Multi-CVE Audit** | **CVE-2026-114925** / **CVE-2026-114863** | `CRITICAL 9.8` | Oracle EBS `12.2.3`–`12.2.15`, Oracle APEX `<= 24.1.22`, `<= 24.2.21`, `<= 26.1.5`, `26.2.0` (6 CVEs) | [`plugins/oracle_ebs_apex/`](plugins/oracle_ebs_apex/) |
| **TYPO3 CMS Core Authentication & Deserialization Audit** | **CVE-2026-119623** | `CRITICAL 9.4` | TYPO3 CMS `< 10.4.63`, `< 11.5.57`, `< 12.4.52`, `< 13.4.40`, `< 14.3.12` | [`plugins/typo3_cms/`](plugins/typo3_cms/) |
| **mailcow: dockerized Host Header & Auth Bypass Audit** | **CVE-2026-125757** | `CRITICAL 9.4` | mailcow: dockerized `< 2026-11` | [`plugins/mailcow/`](plugins/mailcow/) |
| **FleetDM MDM Enrollment & SAML Auth Bypass Audit** | **CVE-2026-130759** | `CRITICAL 9.4` | FleetDM `4.71 < 4.88.2`, `4.89 < 4.89.3`, `4.90 < 4.90.3`, `4.91 < 4.91.2`, `4.92 < 4.92.3` | [`plugins/fleetdm/`](plugins/fleetdm/) |
| **N-able N-central RMM Authentication & Command Audit** | **CVE-2026-129280** | `CRITICAL 9.3` | N-able N-central `< 2026.4.1 HF3` | [`plugins/nable_ncentral/`](plugins/nable_ncentral/) |
| **NocoDB OAuth / JWT Token Authentication Bypass Audit** | **CVE-2026-130730** | `CRITICAL 9.3` | NocoDB `< 2026.10.1` | [`plugins/nocodb/`](plugins/nocodb/) |
| **SolarWinds Serv-U MFT Privilege Escalation & IDOR Audit** | **CVE-2026-123172** / **CVE-2026-82322** | `CRITICAL 9.1` | SolarWinds Serv-U `<= 2026.3` (`< 2026.4`, `15.5.x`) (9 CVEs) | [`plugins/solarwinds_servu/`](plugins/solarwinds_servu/) |
| **Joomla! CMS Multi-CVE Version Compliance Audit** | **CVE-2026-129393** / **CVE-2026-123214** | `CRITICAL 9.4` | Joomla! CMS `1.6.0`–`5.4.10` (`< 5.4.11`), `6.0.0`–`6.2.0` (`< 6.2.1`) (4 CVEs) | [`plugins/joomla/`](plugins/joomla/) |
| **MediaWiki & Extensions Multi-CVE Compliance Audit** | **CVE-2026-132726** / **CVE-2026-132669** | `CRITICAL 9.3` | MediaWiki `1.43 < 1.43.12`, `1.45 < 1.45.7`, `1.46 < 1.46.3`, `1.47.0` (4 CVEs) | [`plugins/mediawiki/`](plugins/mediawiki/) |
| **Poste.io Mail Server DMARC RCE Compliance Audit** | **CVE-2026-127027** | `CRITICAL 9.2` | Poste.io Mail Server `< 2.5.22` (`<= 2.5.21`) | [`plugins/poste_io/`](plugins/poste_io/) |
| **Splunk Enterprise & SOAR Multi-CVE Compliance Audit** | **CVE-2026-76536** / **CVE-2026-131253** | `CRITICAL 9.9` | Splunk Enterprise `< 9.4.17`/`10.0.12`/`10.2.9`/`10.4.5`/`10.6.1`, SOAR `< 8.8.0`, ES `< 8.7.0` (5 CVEs) | [`plugins/splunk_enterprise/`](plugins/splunk_enterprise/) |
| **VMware vCenter Server Directory Service Auth Bypass Audit** | **CVE-2026-123890** / **CVE-2026-123903** | `CRITICAL 9.8` | VMware vCenter Server `9.1 < 9.1.2`, `9.0 < 9.0.2.0300`, `8.0 < 8.0 U3m`, `5.x < 5.2.5` (2 CVEs) | [`plugins/vmware_vcenter/`](plugins/vmware_vcenter/) |
| **OpenCTI Platform Version Compliance Audit** | **CVE-2026-104840** | `CRITICAL 9.2` | OpenCTI `< 7.260428.0` | [`plugins/opencti/`](plugins/opencti/) |
| **phpMyFAQ Version Compliance Audit** | **CVE-2026-130369** / **CVE-2026-130371** | `CRITICAL 9.2` | phpMyFAQ `< 4.1.12`, `4.2.0-alpha`–`< 4.2.0-RC.2` | [`plugins/phpmyfaq/`](plugins/phpmyfaq/) |
| **SAP Web Dispatcher & NetWeaver Compliance Audit** | **CVE-2026-89126** | `CRITICAL 10.0` | SAP Web Dispatcher & ICM `7.22`–`9.21` | [`plugins/sap_netweaver/`](plugins/sap_netweaver/) |
| **Microsoft SharePoint Server Version Compliance Audit** | **CVE-2026-70193** / **CVE-2026-120002** | `CRITICAL 9.9` | SharePoint Server Subscription (`< 16.0.20326.20190`) / 2019 / 2016 (Nov 2026 PU) | [`plugins/sharepoint/`](plugins/sharepoint/) |
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
│   ├── wordpress/                         # Dedicated WordPress & WooCommerce plugins hub (23 plugins)
│   │   ├── README.md                      # WordPress security plugins catalog
│   │   └── wp_*/                          # Individual WordPress plugin auditors
│   └── ...                                # 37 enterprise & infrastructure plugin directories
│
└── tests/                                 # Automated unit test suite (334 tests)
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
