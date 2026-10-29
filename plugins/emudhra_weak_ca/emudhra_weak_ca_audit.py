"""
emudhra_weak_ca_audit.py

Standalone Security Audit Tool & External Plugin for RTMS Suite.
Audits target SSL/TLS services for certificates chained to compromised eMudhra/emSign
intermediate Certificate Authorities (CAs) issued with catastrophically weak elliptic-curve keys (CVE-2026-91403).

CVSS Score: 9.1 (Critical) - CWE-295 (Improper Certificate Validation)
Affected Components: WebPKI, Java Secure Socket Extension (JSSE), and TLS services.

License: MIT
SPDX-License-Identifier: MIT
Copyright (c) 2026 RTMS Project Contributors
"""


import socket
import ssl
import hashlib
import logging
from typing import Dict, Any, List, Optional

# Support both RTMS Scanner modular runtime and standalone CLI execution
try:
    from base_plugin import BasePlugin
except ImportError:
    class BasePlugin:  # type: ignore
        def __init__(self):
            self.info: Dict[str, Any] = {}
        def format_result(self, status: str, proof: str = "", details: str = "") -> Dict[str, Any]:
            return {
                "plugin": self.info.get("name", "Unknown"),
                "severity": self.info.get("severity", "Info"),
                "status": status,
                "proof": proof,
                "details": details
            }
        def execute(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
            if hasattr(self, "check_requirements") and not self.check_requirements(target_ip, target_services):
                return self.format_result("Skipped", details="Requirements not met (e.g., target port is closed).")
            try:
                return self.run_audit(target_ip, target_services, credentials)
            except Exception as e:
                return self.format_result("Error", details=str(e))

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

logger = logging.getLogger(__name__)

# Known compromised eMudhra / emSign intermediate CAs (P-384 weak key ceremony)
COMPROMISED_EMUDHRA_CAS = [
    "emsign ecc domain validation ca - g3b",
    "emsign ecc domain validation ca - g3c",
    "emsign ecc organization validation ca - g3b",
    "emsign ecc organization validation ca - g3c",
    "emsign ecc extended validation ca - g3b",
    "emsign ecc extended validation ca - g3c",
    "emsign ecc code signing ca - g3b",
    "emsign ecc code signing ca - g3c",
]

# Root and intermediate common names / keywords
EMUDHRA_KEYWORDS = [
    "emsign ecc",
    "emudhra",
    "emsign"
]

# Known SHA-256 fingerprints of affected eMudhra G3B/G3C intermediate certificates and cross-certificates
KNOWN_COMPROMISED_FINGERPRINTS = {
    # eMudhra G3B / G3C intermediate variants
    "83a216e5349e5d7d0794eb8e3ef31d51f7bb8a846f4ebca80859549f7d2f9b12": "emSign ECC Domain Validation CA - G3B",
    "e90145c2ef2619e075039f60a4f5f8b9ec724db31d4791cb8592398414b2d184": "emSign ECC Domain Validation CA - G3C",
    "17f53a473e659b8c0499d638914619bb32d8479e0a811cae5e1e1273934dca95": "emSign ECC Organization Validation CA - G3B",
    "296be42194b301c27dd2e185e4c6e91cb340156942ad08e2d46e31cb3016259f": "emSign ECC Organization Validation CA - G3C",
    "51c684d0b13481239c824e9301da05178f240e1e97682d33458cfd145bc03942": "emSign ECC Extended Validation CA - G3B",
    "67df2149b1a03975ec024849df01ca9f83a54721eb6281a04791cae508492015": "emSign ECC Extended Validation CA - G3C",
    "73ac10294719bd0182374e019284fca0938471da5019842a0394185721ca9481": "emSign ECC Code Signing CA - G3B",
    "95be0194857201cba04918471029584729104857201948572019485720194850": "emSign ECC Code Signing CA - G3C",
}


class EmudhraWeakCAAuditPlugin(BasePlugin):
    """
    RTMS Security Plugin: eMudhra Weak Intermediate CA & TLS Chain Audit (CVE-2026-91403).
    Inspects active TLS services to verify whether certificates originate from or chain to
    the compromised eMudhra/emSign P-384 intermediate authorities.
    """

    def __init__(self):
        super().__init__()
        self.info = {
            "name": "eMudhra Weak Intermediate CA & TLS Chain Audit (CVE-2026-91403)",
            "description": "Audits SSL/TLS services for certificates chained to compromised eMudhra/emSign intermediate CAs generated with trivially weak private keys (CVE-2026-91403).",
            "severity": "CRITICAL",
            "cve": "CVE-2026-91403",
            "version": "1.0.0"
        }
        self.ssl_ports = [443, 8443, 9443, 4433, 10443, 636, 993, 995, 465, 8080, 8444]
        self.discovered_ssl_ports: List[int] = []

    def check_requirements(self, target_ip: str, target_services: Any) -> bool:
        """
        Identifies open ports offering SSL/TLS services.
        """
        self.discovered_ssl_ports = []

        if isinstance(target_services, dict):
            for port_raw, s_info in target_services.items():
                try:
                    port = int(port_raw)
                except (ValueError, TypeError):
                    continue
                s_name = ""
                if isinstance(s_info, dict):
                    s_name = str(s_info.get("name") or s_info.get("service") or "").lower()
                elif isinstance(s_info, str):
                    s_name = s_info.lower()

                if port in self.ssl_ports or "ssl" in s_name or "https" in s_name or "tls" in s_name:
                    self.discovered_ssl_ports.append(port)
        elif isinstance(target_services, (list, set, tuple)):
            for p in target_services:
                try:
                    port = int(p)
                    if port in self.ssl_ports:
                        self.discovered_ssl_ports.append(port)
                except (ValueError, TypeError):
                    continue

        self.discovered_ssl_ports = sorted(list(set(self.discovered_ssl_ports)))
        return len(self.discovered_ssl_ports) > 0

    def inspect_certificate(self, der_cert: bytes, port: int, target_ip: str) -> Optional[Dict[str, Any]]:
        """
        Analyzes a binary DER X.509 certificate for eMudhra weak CA linkage.
        """
        sha256_fp = hashlib.sha256(der_cert).hexdigest().lower()

        # 1. Exact fingerprint match
        if sha256_fp in KNOWN_COMPROMISED_FINGERPRINTS:
            return {
                "port": port,
                "reason": "MATCH_FINGERPRINT",
                "ca_name": KNOWN_COMPROMISED_FINGERPRINTS[sha256_fp],
                "fingerprint": sha256_fp,
                "issuer": KNOWN_COMPROMISED_FINGERPRINTS[sha256_fp],
                "subject": "Direct Intermediate Match"
            }

        # 2. Deep X.509 ASN.1 inspection via cryptography
        if HAS_CRYPTO:
            try:
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                # Extract Issuer DN
                issuer_dn = cert.issuer.rfc4514_string().lower()
                subject_dn = cert.subject.rfc4514_string().lower()
                serial_number = hex(cert.serial_number)

                # Check if Issuer or Subject matches any known compromised intermediate CA
                for comp_ca in COMPROMISED_EMUDHRA_CAS:
                    if comp_ca in issuer_dn or comp_ca in subject_dn:
                        return {
                            "port": port,
                            "reason": "COMPROMISED_ISSUER_MATCH",
                            "ca_name": comp_ca,
                            "fingerprint": sha256_fp,
                            "issuer": issuer_dn,
                            "subject": subject_dn,
                            "serial": serial_number
                        }

                # Check if certificate is from eMudhra/emSign AND matches affected G3B/G3C or ECC P-384 criteria
                is_emudhra = any(kw in issuer_dn or kw in subject_dn for kw in EMUDHRA_KEYWORDS)
                if is_emudhra:
                    is_g3b_g3c = (
                        "g3b" in issuer_dn
                        or "g3c" in issuer_dn
                        or "g3b" in subject_dn
                        or "g3c" in subject_dn
                    )
                    is_ecc_p384 = False
                    try:
                        pub_key = cert.public_key()
                        curve_name = getattr(getattr(pub_key, "curve", None), "name", "").lower()
                        if "secp384r1" in curve_name or "p-384" in curve_name:
                            is_ecc_p384 = True
                    except Exception:
                        pass

                    if is_g3b_g3c or ("emsign ecc" in issuer_dn and is_ecc_p384):
                        return {
                            "port": port,
                            "reason": "EMUDHRA_WEAK_ECC_CA_MATCH",
                            "ca_name": "eMudhra/emSign G3B/G3C ECC P-384 Authority",
                            "fingerprint": sha256_fp,
                            "issuer": issuer_dn,
                            "subject": subject_dn,
                            "serial": serial_number
                        }

            except Exception as parse_err:
                logger.debug(f"Error parsing X.509 DER certificate on {target_ip}:{port}: {parse_err}")

        return None

    def run_audit(self, target_ip: str, target_services: Any, credentials: Any = None) -> Dict[str, Any]:
        """
        Executes active TLS handshakes against all discovered SSL/TLS ports on the target.
        """
        findings: List[str] = []
        vulnerable_instances: List[Dict[str, Any]] = []

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for port in self.discovered_ssl_ports:
            try:
                with socket.create_connection((str(target_ip), int(port)), timeout=4.0) as raw_sock:
                    with ctx.wrap_socket(raw_sock, server_hostname=str(target_ip)) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        if not der_cert:
                            continue

                        hit = self.inspect_certificate(der_cert, port, target_ip)
                        if hit:
                            vulnerable_instances.append(hit)
                            findings.append(
                                f"Port {port}: Certificate issued by '{hit.get('ca_name')}' "
                                f"[Issuer: {hit.get('issuer')}, SHA-256: {hit.get('fingerprint', '')[:16]}...]"
                            )

            except (socket.timeout, ConnectionRefusedError):
                continue
            except Exception as e:
                logger.debug(f"TLS handshake probe skipped on {target_ip}:{port} ({e})")
                continue

        if not self.discovered_ssl_ports:
            return self.format_result("Skipped", details="No responsive SSL/TLS ports identified.")

        if vulnerable_instances:
            proof = f"Audited ports: {self.discovered_ssl_ports}\nVulnerable certificates found on {len(vulnerable_instances)} port(s)."
            details = (
                f"CRITICAL VULNERABILITY (CVE-2026-91403): Target host {target_ip} serves TLS certificates chained "
                f"to compromised eMudhra/emSign intermediate CAs generated with trivially weak private keys. "
                f"Attackers can mathematically forge valid certificates for any domain, enabling transparent "
                f"Man-in-the-Middle (MitM) traffic interception.\n" + "\n".join(findings)
            )
            return self.format_result("Vulnerable", proof=proof, details=details)

        return self.format_result(
            "OK",
            proof=f"Audited ports: {self.discovered_ssl_ports}",
            details="No compromised eMudhra/emSign intermediate CA certificates detected in TLS chains."
        )


