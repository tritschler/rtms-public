# RTMS Community Security Plugins — Full Catalog

[![Platform](https://img.shields.io/badge/Platform-RTMS_Suite-blue.svg)](https://3ts.ai)
[![Plugins](https://img.shields.io/badge/Plugins-92-brightgreen.svg)](README.md)
[![CVEs Covered](https://img.shields.io/badge/Critical_CVEs-218%2B-red.svg)](https://nvd.nist.gov/)

This catalog indexes all standalone defensive audit tools and **[RTMS Cybersecurity Suite](https://3ts.ai)** plugins available in this repository, grouped by technology domain.

* 👉 Return to **[Main Repository Overview (`README.md`)](README.md)**
* 👉 Browse the dedicated **[WordPress & WooCommerce Security Catalog (`plugins/wordpress/README.md`)](plugins/wordpress/README.md)**

---

## 🛡️ 1. Network Appliances, Firewalls & VPN Gateways

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory | Quick Audit Command |
|:---|:---:|:---:|:---|:---:|:---|
| **Citrix NetScaler Console & ADC Gateway Audit** | **CVE-2026-120869** / **CVE-2026-120864** | `CRITICAL 9.5` | NetScaler ADC/Gateway `< 14.1-73.57`, `< 13.1-64.39` (10 CVEs) | [`plugins/citrix_netscaler/`](plugins/citrix_netscaler/) | `python plugins/citrix_netscaler/citrix_netscaler_cve_2026_120869_audit.py <target>` |
| **Fortinet FortiOS Version Compliance Audit** | **CVE-2026-126259** | `CRITICAL 9.8` | FortiOS `7.0.0`–`7.0.19`, `7.2.0`–`7.2.13`, `7.4.0`–`7.4.12`, `7.6.0`–`7.6.7`, `8.0.0`–`8.0.1` | [`plugins/fortios/`](plugins/fortios/) | `python plugins/fortios/fortios_cve_2026_126259_audit.py <target>` |
| **Fortinet FortiManager Version Compliance Audit** | **CVE-2026-126261** | `CRITICAL 9.8` | FortiManager `7.2.0`–`7.2.8`, `7.4.0`–`7.4.5`, `7.6.0`–`7.6.7`, `8.0.0` | [`plugins/fortimanager/`](plugins/fortimanager/) | `python plugins/fortimanager/fortimanager_cve_2026_126261_audit.py <target>` |
| **WatchGuard Fireware OS & SonicWall SMA1000 Audit** | **CVE-2026-93866** | `CRITICAL 10.0` | Fireware OS `< 12.11.9` / `< 2026.2.1`, SonicWall SMA1000 `< 12.4.3-03312` | [`plugins/watchguard_fireware/`](plugins/watchguard_fireware/) | `python plugins/watchguard_fireware/watchguard_fireware_cve_2026_93866_audit.py <target>` |
| **SonicWall GMS Internal File Read Audit** | **CVE-2026-109593** | `CRITICAL 9.1` | SonicWall Global Management System `<= 9.5.2` | [`plugins/sonicwall_gms/`](plugins/sonicwall_gms/) | `python plugins/sonicwall_gms/sonicwall_gms_cve_2026_109593_audit.py <target>` |
| **Barracuda Email Security Gateway Auth Bypass Audit** | **CVE-2026-116606** | `CRITICAL 9.3` | Barracuda Email Security Gateway `< 9.4.0.030` | [`plugins/barracuda_esg/`](plugins/barracuda_esg/) | `python plugins/barracuda_esg/barracuda_esg_cve_2026_116606_audit.py <target>` |
| **Synology DiskStation Manager Version Audit** | **CVE-2026-120382** / **CVE-2026-76954** | `CRITICAL 9.8` | Synology DSM `< 7.1.1-42962-10`, `< 7.2.1-69057-14`, `< 7.2.2-72806-11`, `< 7.3.2-86009-6`, `< 7.4.1-90080-2` | [`plugins/synology_dsm/`](plugins/synology_dsm/) | `python plugins/synology_dsm/synology_dsm_cve_2026_76954_audit.py <target>` |
| **F5 BIG-IP TMOS & APM Version Compliance Audit** | **CVE-2026-123637** | `CRITICAL 9.3` | F5 BIG-IP `17.1.x < 17.1.3.6`, `17.5.x < 17.5.1.10`, `21.1.x < 21.1.0.2` (7 CVEs) | [`plugins/f5_bigip/`](plugins/f5_bigip/) | `python plugins/f5_bigip/f5_bigip_cve_2026_123637_audit.py <target>` |

---

## 🔑 2. Identity, IAM, SSO & PKI Infrastructure

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory | Quick Audit Command |
|:---|:---:|:---:|:---|:---:|:---|
| **OpenAM Live Session Token & Auth Bypass Audit** | **CVE-2026-123551** | `CRITICAL 10.0` | OpenAM `< 16.1.4` (`14.0.0`–`16.1.3`) | [`plugins/openam/`](plugins/openam/) | `python plugins/openam/openam_cve_2026_123551_audit.py <target>` |
| **Keycloak SAML HTTP-Redirect Signature Audit** | **CVE-2026-117691** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.0` | [`plugins/keycloak/`](plugins/keycloak/) | `python plugins/keycloak/keycloak_cve_2026_117691_audit.py <target>` |
| **Keycloak Client Management JS Policy RCE Audit** | **CVE-2026-120984** | `CRITICAL 9.1` | Keycloak / RH-SSO `< 26.2.5` | [`plugins/keycloak_client_mgmt/`](plugins/keycloak_client_mgmt/) | `python plugins/keycloak_client_mgmt/keycloak_cve_2026_120984_audit.py <target>` |
| **IBM API Connect Auth Bypass & RCE Audit** | **CVE-2026-17301** / **CVE-2026-17410** | `CRITICAL 9.9` | IBM API Connect `10.0.8.0`–`10.0.8.12`, `12.1.0.0`–`12.1.1.2` | [`plugins/ibm_api_connect/`](plugins/ibm_api_connect/) | `python plugins/ibm_api_connect/ibm_api_connect_cve_2026_17301_audit.py <target>` |
| **eMudhra Weak Intermediate CA Audit** | **CVE-2026-91403** | `CRITICAL 9.1` | WebPKI, Java JSSE, TLS endpoints | [`plugins/emudhra_weak_ca/`](plugins/emudhra_weak_ca/) | `python plugins/emudhra_weak_ca/emudhra_weak_ca_audit.py <target>` |
| **Cyrus SASL SRP Authentication Bypass Audit** | **CVE-2026-129483** | `CRITICAL 9.3` | Cyrus SASL (`libsasl2`) `<= 2.1.28` | [`plugins/cyrus_sasl/`](plugins/cyrus_sasl/) | `python plugins/cyrus_sasl/cyrus_sasl_cve_2026_129483_audit.py <target>` |

---

## ⚙️ 3. Web Servers, Runtimes, DevOps & Containers

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory | Quick Audit Command |
|:---|:---:|:---:|:---|:---:|:---|
| **FrankenPHP Application Server Compliance Audit** | **CVE-2026-128014** / **CVE-2026-128023** | `CRITICAL 9.3` | FrankenPHP `< 1.13.2` (`< 1.13.0`, `< 1.1.11`) | [`plugins/frankenphp/`](plugins/frankenphp/) | `python plugins/frankenphp/frankenphp_cve_2026_128014_audit.py <target>` |
| **PHP Core Stale Global State RCE Audit (PHP2Shell)** | **CVE-2026-109619** | `CRITICAL 9.2` | PHP 5.4 to 8.5.11, FastCGI, PAN-OS | [`plugins/php2shell/`](plugins/php2shell/) | `python plugins/php2shell/php2shell_cve_2026_109619_audit.py <target>` |
| **GitLab CE/EE Version Compliance Audit** | **CVE-2026-110264** | `CRITICAL 10.0` | GitLab CE/EE `< 19.2.6`, `< 19.3.4`, `< 19.4.2` | [`plugins/gitlab/`](plugins/gitlab/) | `python plugins/gitlab/gitlab_cve_2026_110264_audit.py <target>` |
| **Red Hat Quay Version Compliance Audit** | **CVE-2026-110697** | `CRITICAL 9.9` | Red Hat Quay `3.12`–`3.18` (`< 3.12.11` to `< 3.18.2`) | [`plugins/redhat_quay/`](plugins/redhat_quay/) | `python plugins/redhat_quay/redhat_quay_cve_2026_110697_audit.py <target>` |
| **SUSE Rancher Manager Meta-Proxy & Fleet Audit** | **CVE-2026-88811** | `CRITICAL 9.1` | SUSE Rancher `2.13`–`2.15` (`< 2.13.12`/`2.14.8`/`2.15.4`) | [`plugins/rancher/`](plugins/rancher/) | `python plugins/rancher/rancher_cve_2026_88811_audit.py <target>` |
| **Sonatype Nexus Repository 3 SAML/OIDC Bypass Audit** | **CVE-2026-113373** | `CRITICAL 9.1` | Sonatype Nexus Repository 3 `3.86.0`–`3.97.1` (`< 3.98.0`) | [`plugins/nexus_repository/`](plugins/nexus_repository/) | `python plugins/nexus_repository/nexus_cve_2026_113373_audit.py <target>` |
| **pgAdmin 4 psql \copy RCE & Lockout Bypass Audit** | **CVE-2026-116241** | `CRITICAL 9.4` | pgAdmin 4 Server Mode `< 9.19` | [`plugins/pgadmin4/`](plugins/pgadmin4/) | `python plugins/pgadmin4/pgadmin4_cve_2026_116241_audit.py <target>` |
| **Redpanda Connect Version Compliance Audit** | **CVE-2026-123270** | `CRITICAL 9.8` | Redpanda Connect `4.39`–`4.110` (`< 4.111.0`) | [`plugins/redpanda_connect/`](plugins/redpanda_connect/) | `python plugins/redpanda_connect/redpanda_connect_cve_2026_123270_audit.py <target>` |
| **imgproxy ICO Loader Version Compliance Audit** | **CVE-2026-123614** | `CRITICAL 9.3` | imgproxy `4.0.0`–`4.0.15` (`< 4.0.16`) | [`plugins/imgproxy/`](plugins/imgproxy/) | `python plugins/imgproxy/imgproxy_cve_2026_123614_audit.py <target>` |
| **vsftpd FTPS Data Channel Hijacking Audit** | **CVE-2026-119568** | `CRITICAL 9.1` | vsftpd `<= 3.0.5` (Ubuntu, Debian, RHEL) | [`plugins/vsftpd/`](plugins/vsftpd/) | `python plugins/vsftpd/vsftpd_cve_2026_119568_audit.py <target>` |
| **Google Chrome & Headless Chromium Sandbox Audit** | **CVE-2026-134401** / **CVE-2026-131088** / **CVE-2026-126885** | `CRITICAL 9.6` | Google Chrome / Headless Chromium `< 158.0.8127.88` (19 CVEs) | [`plugins/google_chrome/`](plugins/google_chrome/) | `python plugins/google_chrome/google_chrome_cve_2026_126885_audit.py <target>` |
| **Dokploy PaaS Version Compliance Audit** | **CVE-2026-129433** | `CRITICAL 9.4` | Dokploy `< 0.31.1` (`<= 0.31.0`) | [`plugins/dokploy/`](plugins/dokploy/) | `python plugins/dokploy/dokploy_cve_2026_129433_audit.py <target>` |
| **Apache TomEE & OpenEJB Version Compliance Audit** | **CVE-2026-87756** | `CRITICAL 9.8` | Apache TomEE / OpenEJB `< 10.3.0`, `11.0.0-M1` (9 CVEs) | [`plugins/apache_tomee/`](plugins/apache_tomee/) | `python plugins/apache_tomee/apache_tomee_cve_2026_87756_audit.py <target>` |
| **AdminNeo Database Manager Compliance Audit** | **CVE-2026-130366** / **CVE-2026-130380** | `CRITICAL 9.2` | AdminNeo `< 5.9.1` | [`plugins/adminneo/`](plugins/adminneo/) | `python plugins/adminneo/adminneo_cve_2026_130366_audit.py <target>` |
| **Arize AI Phoenix Version Compliance Audit** | **CVE-2026-53998** | `CRITICAL 10.0` | Arize AI Phoenix `>= 13.0.0, < 15.7.0` | [`plugins/arize_phoenix/`](plugins/arize_phoenix/) | `python plugins/arize_phoenix/arize_phoenix_cve_2026_53998_audit.py <target>` |
| **Oracle MySQL Server & Cluster Compliance Audit** | **CVE-2026-114952** | `CRITICAL 9.1` | MySQL Server `8.4.0`–`8.4.13`, `9.7.0`–`9.7.4`, `26.10` & Cluster `8.0.0`–`8.0.50` | [`plugins/mysql/`](plugins/mysql/) | `python plugins/mysql/mysql_cve_2026_114952_audit.py <target>` |
| **Oracle WebLogic Server Version Compliance Audit** | **CVE-2026-91569** | `CRITICAL 10.0` | Oracle WebLogic Server `12.2.1.4.0`, `14.1.1.0.0`, `14.1.2.0.0`, `15.1.1.0.0` (7 CVEs) | [`plugins/oracle_weblogic/`](plugins/oracle_weblogic/) | `python plugins/oracle_weblogic/oracle_weblogic_cve_2026_91569_audit.py <target>` |
| **NGINX Open Source & NGINX Plus Version Compliance Audit** | **CVE-2026-121810** | `CRITICAL 9.2` | NGINX Open Source `< 1.30.7`, `1.31.0`–`1.31.8` (`< 1.31.9`) & NGINX Plus (5 CVEs) | [`plugins/nginx/`](plugins/nginx/) | `python plugins/nginx/nginx_cve_2026_121810_audit.py <target>` |
| **JetBrains TeamCity Version Compliance Audit** | **CVE-2026-132234** / **CVE-2026-132891** | `CRITICAL 9.9` | JetBrains TeamCity `< 2025.11.8` & `2026.1.0`–`2026.1.3` (`< 2026.1.4`) (5 CVEs) | [`plugins/jetbrains_teamcity/`](plugins/jetbrains_teamcity/) | `python plugins/jetbrains_teamcity/jetbrains_teamcity_cve_2026_132234_audit.py <target>` |
| **PHP & PHP-FPM Multi-CVE Version Compliance Audit** | **CVE-2026-129289** | `CRITICAL 9.2` | PHP / PHP-FPM `8.2 < 8.2.36`, `8.3 < 8.3.37`, `8.4 < 8.4.28`, `8.5 < 8.5.13` (7 CVEs) | [`plugins/php_fpm/`](plugins/php_fpm/) | `python plugins/php_fpm/php_fpm_cve_2026_129289_audit.py <target>` |
| **Apache Tomcat Multi-CVE Version Compliance Audit** | **CVE-2026-133325** | `CRITICAL 9.8` | Apache Tomcat `< 11.0.30`, `< 10.1.63`, `< 9.0.125`, EOL `<= 8.5.100` (4 CVEs) | [`plugins/apache_tomcat/`](plugins/apache_tomcat/) | `python plugins/apache_tomcat/apache_tomcat_cve_2026_133325_audit.py <target>` |
| **Postgres Enterprise Manager (PEM) Multi-CVE Audit** | **CVE-2026-132660** | `CRITICAL 9.4` | EDB Postgres Enterprise Manager (PEM) `< 10.6.1` (3 CVEs) | [`plugins/postgres_enterprise_manager/`](plugins/postgres_enterprise_manager/) | `python plugins/postgres_enterprise_manager/postgres_enterprise_manager_cve_2026_132660_audit.py <target>` |
| **Fastify Middleware (`@fastify/express` & `@fastify/middie`) Audit** | **CVE-2026-133120** / **CVE-2026-133250** | `CRITICAL 9.1` | `@fastify/express < 4.0.10`, `@fastify/middie <= 9.3.7` (5 CVEs) | [`plugins/fastify/`](plugins/fastify/) | `python plugins/fastify/fastify_cve_2026_133120_audit.py <target>` |
| **SurrealDB Embedded JS Capability Bypass Audit** | **CVE-2026-134292** | `CRITICAL 9.3` | SurrealDB `>= 1.0.0, < 4.0.0` | [`plugins/surrealdb/`](plugins/surrealdb/) | `python plugins/surrealdb/surrealdb_cve_2026_134292_audit.py <target>` |
| **Cribl Stream REST Collector Pagination Compliance Audit** | **CVE-2026-115899** | `CRITICAL 9.3` | Cribl Stream `<= 4.20.4` (`< 4.20.5`) | [`plugins/cribl_stream/`](plugins/cribl_stream/) | `python plugins/cribl_stream/cribl_stream_cve_2026_115899_audit.py <target>` |
| **FFmpeg libavfilter Heap Out-of-Bounds Compliance Audit** | **CVE-2026-135736** / **CVE-2026-135743** | `CRITICAL 9.2` | FFmpeg `4.3` / `4.4` to `< 9.1` | [`plugins/ffmpeg/`](plugins/ffmpeg/) | `python plugins/ffmpeg/ffmpeg_cve_2026_135736_audit.py <target>` |

---

## 🏢 4. Enterprise Apps, ERP, ITSM, Groupware & Healthcare

| Plugin Name | Target CVE | Severity | Affected Systems | Plugin Directory | Quick Audit Command |
|:---|:---:|:---:|:---|:---:|:---|
| **Splunk Enterprise & SOAR Multi-CVE Compliance Audit** | **CVE-2026-76536** / **CVE-2026-131253** | `CRITICAL 9.9` | Splunk Enterprise `< 9.4.17`/`10.0.12`/`10.2.9`/`10.4.5`/`10.6.1`, SOAR `< 8.8.0`, ES `< 8.7.0` (5 CVEs) | [`plugins/splunk_enterprise/`](plugins/splunk_enterprise/) | `python plugins/splunk_enterprise/splunk_enterprise_cve_2026_76536_audit.py <target>` |
| **VMware vCenter Server Directory Service Auth Bypass Audit** | **CVE-2026-123890** | `CRITICAL 9.8` | VMware vCenter Server `9.1 < 9.1.1.0200`, `9.0 < 9.0.2.0200`, `8.0 < 8.0 U3m`, `5.x < 5.2.5` | [`plugins/vmware_vcenter/`](plugins/vmware_vcenter/) | `python plugins/vmware_vcenter/vmware_vcenter_cve_2026_123890_audit.py <target>` |
| **SAP Web Dispatcher & NetWeaver Compliance Audit** | **CVE-2026-89126** | `CRITICAL 10.0` | SAP Web Dispatcher & ICM `7.22`–`9.21` | [`plugins/sap_netweaver/`](plugins/sap_netweaver/) | `python plugins/sap_netweaver/sap_netweaver_cve_2026_89126_audit.py <target>` |
| **Microsoft SharePoint Server Version Compliance Audit** | **CVE-2026-70193** / **CVE-2026-120002** | `CRITICAL 9.9` | SharePoint Server Subscription (`< 16.0.20326.20190`) / 2019 / 2016 (Nov 2026 PU) | [`plugins/sharepoint/`](plugins/sharepoint/) | `python plugins/sharepoint/sharepoint_cve_2026_120002_audit.py <target>` |
| **OpenEMR Multi-CVE Version Compliance Audit** | **CVE-2026-126473** / **CVE-2026-124445** | `CRITICAL 9.4` | OpenEMR `< 8.4.0` (`< 8.3.0`) (6 CVEs) | [`plugins/openemr/`](plugins/openemr/) | `python plugins/openemr/openemr_cve_2026_124445_audit.py <target>` |
| **GLPI Two-Factor Authentication Bypass Audit** | **CVE-2026-52848** | `CRITICAL 9.2` | GLPI `11.0.0` to `11.0.7` (`< 11.0.8`) | [`plugins/glpi/`](plugins/glpi/) | `python plugins/glpi/glpi_cve_2026_52848_audit.py <target>` |
| **Zoho ManageEngine ITSM, M365 Manager & DDI Audit** | **CVE-2026-12591** / **CVE-2026-12507** | `CRITICAL 9.9` | M365 Manager Plus `< 4818`, ServiceDesk Plus `< 15290`, DDI Central `< 6301` | [`plugins/manageengine_itsm/`](plugins/manageengine_itsm/) | `python plugins/manageengine_itsm/manageengine_itsm_cve_2026_12591_audit.py <target>` |
| **Zoho ManageEngine Log360 & EventLog Analyzer Audit** | **CVE-2026-13594** | `CRITICAL 9.1` | ManageEngine Log360 & EventLog Analyzer `<= 13062` | [`plugins/manageengine_log360/`](plugins/manageengine_log360/) | `python plugins/manageengine_log360/manageengine_cve_2026_13594_audit.py <target>` |
| **Ivanti Endpoint Manager Version Compliance Audit** | **CVE-2026-121653** | `CRITICAL 9.8` | Ivanti Endpoint Manager `< 2024 SU8` (`< 11.0.6.8`) | [`plugins/ivanti_epm/`](plugins/ivanti_epm/) | `python plugins/ivanti_epm/ivanti_epm_cve_2026_121653_audit.py <target>` |
| **Apache OFBiz Screen Descriptor & Login Key Audit** | **CVE-2026-83542** | `CRITICAL 9.8` | Apache OFBiz `< 24.09.08` | [`plugins/apache_ofbiz/`](plugins/apache_ofbiz/) | `python plugins/apache_ofbiz/apache_ofbiz_cve_2026_83542_audit.py <target>` |
| **Craft CMS Version Compliance Audit** | **CVE-2026-115934** | `CRITICAL 9.3` | Craft CMS `< 4.18.9` & `< 5.11.2` | [`plugins/craft_cms/`](plugins/craft_cms/) | `python plugins/craft_cms/craft_cms_cve_2026_115934_audit.py <target>` |
| **Alinto SOGo Groupware SAML & Sieve Audit** | **CVE-2026-127131** | `CRITICAL 9.1` | Alinto SOGo `< 5.12.7` & `< 2.4.7` | [`plugins/sogo_groupware/`](plugins/sogo_groupware/) | `python plugins/sogo_groupware/sogo_cve_2026_127131_audit.py <target>` |
| **Azul Payara Server & Payara Micro Admin Auth Audit** | **CVE-2026-110003** / **CVE-2026-90908** | `CRITICAL 9.3` | Payara `< 7.6.0` / `< 7.2026.11`, `< 6.44.0`, `< 5.93.0` | [`plugins/azul_payara/`](plugins/azul_payara/) | `python plugins/azul_payara/azul_payara_cve_2026_110003_audit.py <target>` |
| **FreeSWITCH SIP & WebRTC Stack Version Audit** | **CVE-2026-116779** | `CRITICAL 9.8` | FreeSWITCH `< 1.11.3` | [`plugins/freeswitch/`](plugins/freeswitch/) | `python plugins/freeswitch/freeswitch_cve_2026_116779_audit.py <target>` |
| **NoMachine nxwebrunner Web Service Audit** | **CVE-2026-114549** | `CRITICAL 9.8` | NoMachine `nxwebrunner` `<= 9.7.3` | [`plugins/nomachine/`](plugins/nomachine/) | `python plugins/nomachine/nomachine_cve_2026_114549_audit.py <target>` |
| **OpenCTI Platform Version Compliance Audit** | **CVE-2026-104840** | `CRITICAL 9.2` | OpenCTI `< 7.260428.0` | [`plugins/opencti/`](plugins/opencti/) | `python plugins/opencti/opencti_cve_2026_104840_audit.py <target>` |
| **phpMyFAQ Version Compliance Audit** | **CVE-2026-130369** / **CVE-2026-130371** | `CRITICAL 9.2` | phpMyFAQ `< 4.1.12`, `4.2.0-alpha`–`< 4.2.0-RC.2` | [`plugins/phpmyfaq/`](plugins/phpmyfaq/) | `python plugins/phpmyfaq/phpmyfaq_cve_2026_130369_audit.py <target>` |
| **Poste.io Mail Server DMARC RCE Compliance Audit** | **CVE-2026-127027** | `CRITICAL 9.2` | Poste.io Mail Server `< 2.5.22` (`<= 2.5.21`) | [`plugins/poste_io/`](plugins/poste_io/) | `python plugins/poste_io/poste_io_cve_2026_127027_audit.py <target>` |

---

## 🌐 5. WordPress & WooCommerce Ecosystem (34 Plugins)

All 34 WordPress and WooCommerce plugins are indexed in their dedicated catalog:

👉 **[Open the WordPress & WooCommerce Security Plugins Catalog (`plugins/wordpress/README.md`)](plugins/wordpress/README.md)**
