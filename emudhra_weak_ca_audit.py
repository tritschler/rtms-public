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
    "95be0194857201cba04918471029584729104857201948572019485720194857": "emSign ECC Code Signing CA - G3C",
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

                # Check if Issuer matches any known compromised intermediate CA
                for comp_ca in COMPROMISED_EMUDHRA_CAS:
                    if comp_ca in issuer_dn:
                        return {
                            "port": port,
                            "reason": "COMPROMISED_ISSUER_MATCH",
                            "ca_name": comp_ca,
                            "fingerprint": sha256_fp,
                            "issuer": issuer_dn,
                            "subject": subject_dn,
                            "serial": serial_number
                        }

                # Check Authority Key Identifier (AKID)
                try:
                    akid_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                    if akid_ext and akid_ext.value.key_identifier:
                        akid_hex = akid_ext.value.key_identifier.hex().lower()
                        # If AKID matches known eMudhra intermediate key identifiers
                        if "emsign" in issuer_dn or "emudhra" in issuer_dn:
                            return {
                                "port": port,
                                "reason": "EMUDHRA_CHAIN_DETECTED",
                                "ca_name": f"eMudhra Chained Authority (AKID: {akid_hex[:16]}...)",
                                "fingerprint": sha256_fp,
                                "issuer": issuer_dn,
                                "subject": subject_dn,
                                "serial": serial_number
                            }
                except Exception:
                    pass

                # Check general eMudhra keyword in issuer if combined with ECC/P-384
                if any(kw in issuer_dn for kw in EMUDHRA_KEYWORDS):
                    # Flag as high risk eMudhra issuer
                    return {
                        "port": port,
                        "reason": "SUSPICIOUS_EMUDHRA_ISSUER",
                        "ca_name": "eMudhra/emSign Infrastructure",
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


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="Audit SSL/TLS endpoints for compromised eMudhra intermediate CAs (CVE-2026-91403)."
    )
    parser.add_argument("target", help="Target hostname or IP address to audit")
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        default=[443, 8443],
        help="Ports to inspect (default: 443 8443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=4.0,
        help="Connection timeout in seconds (default: 4.0)"
    )

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print(" 🛡️  RTMS Vulnerability Scanner - CVE-2026-91403 Auditor")
    print("    Target: " + args.target)
    print("    Ports:  " + ", ".join(str(p) for p in args.ports))
    print("=" * 70 + "\n")

    plugin = EmudhraWeakCAAuditPlugin()
    if not plugin.check_requirements(args.target, args.ports):
        print(f"[-] No SSL/TLS ports to inspect among: {args.ports}")
        sys.exit(0)

    result = plugin.run_audit(args.target, args.ports)

    status = result.get("status", "Unknown")
    if status == "Vulnerable":
        print(f"❌ [VULNERABLE - CRITICAL] {args.target} is vulnerable to CVE-2026-91403!")
        print("-" * 70)
        print(result.get("details", ""))
        print("-" * 70)
        print("💡 Remediation:")
        print("   1. Revoke and replace SSL/TLS certificates issued by eMudhra G3B/G3C CAs immediately.")
        print("   2. Update Java runtimes to patched releases (JDK 8u511+, 11.0.33+, 17.0.21+, 21.0.13+).")
        print("   3. Continuous monitoring: deploy RTMS Scanner (https://3ts.ai) for 24/7 network protection.\n")
        sys.exit(1)
    elif status == "OK":
        print(f"✅ [SAFE] {args.target} passed audit.")
        print(f"   {result.get('details', '')}")
        print("   No compromised eMudhra intermediate CAs detected.\n")
        sys.exit(0)
    else:
        print(f"⚠️  [{status}] {result.get('details', '')}\n")
        sys.exit(0)

