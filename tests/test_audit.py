"""
test_audit.py - Unit tests for eMudhra Weak Intermediate CA Audit Tool (CVE-2026-91403).
"""

import pytest
import datetime
from unittest.mock import MagicMock, patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from plugins.emudhra_weak_ca.emudhra_weak_ca_audit import EmudhraWeakCAAuditPlugin, KNOWN_COMPROMISED_FINGERPRINTS


def generate_self_signed_cert(issuer_cn: str, subject_cn: str = "example.com") -> bytes:
    """Helper to generate a self-signed X.509 DER certificate for testing."""
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_plugin_metadata():
    plugin = EmudhraWeakCAAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-91403"
    assert plugin.info["severity"] == "CRITICAL"
    assert "eMudhra" in plugin.info["name"]


def test_check_requirements():
    plugin = EmudhraWeakCAAuditPlugin()

    # Port in list
    assert plugin.check_requirements("192.168.1.1", [443]) is True
    assert 443 in plugin.discovered_ssl_ports

    # Service dict with HTTPS
    assert plugin.check_requirements("192.168.1.1", {8080: {"name": "https-alt"}}) is True
    assert 8080 in plugin.discovered_ssl_ports

    # Closed or irrelevant ports
    assert plugin.check_requirements("192.168.1.1", [22, 21, 80]) is False
    assert plugin.discovered_ssl_ports == []


def test_inspect_certificate_compromised_issuer():
    plugin = EmudhraWeakCAAuditPlugin()

    # Generate certificate issued by compromised eMudhra intermediate CA
    vuln_der = generate_self_signed_cert("emSign ECC Domain Validation CA - G3B")
    hit = plugin.inspect_certificate(vuln_der, 443, "192.168.1.50")

    assert hit is not None
    assert hit["port"] == 443
    assert hit["reason"] == "COMPROMISED_ISSUER_MATCH"
    assert "emsign ecc domain validation ca - g3b" in hit["ca_name"]


def test_inspect_certificate_safe_issuer():
    plugin = EmudhraWeakCAAuditPlugin()

    # Generate certificate issued by Let's Encrypt / DigiCert
    safe_der = generate_self_signed_cert("Let's Encrypt Authority X3")
    hit = plugin.inspect_certificate(safe_der, 443, "192.168.1.50")

    assert hit is None


def test_inspect_certificate_exact_fingerprint_match():
    plugin = EmudhraWeakCAAuditPlugin()
    known_fp = list(KNOWN_COMPROMISED_FINGERPRINTS.keys())[0]

    with patch("hashlib.sha256") as mock_sha:
        mock_sha.return_value.hexdigest.return_value = known_fp
        hit = plugin.inspect_certificate(b"fake_der", 8443, "192.168.1.50")

        assert hit is not None
        assert hit["port"] == 8443
        assert hit["reason"] == "MATCH_FINGERPRINT"


def test_run_audit_vulnerable_target(mocker):
    plugin = EmudhraWeakCAAuditPlugin()
    vuln_der = generate_self_signed_cert("emSign ECC Extended Validation CA - G3C")

    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = vuln_der

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    mocker.patch("socket.create_connection", return_value=mock_raw_sock)
    mocker.patch("ssl.create_default_context", return_value=mock_ctx)

    plugin.discovered_ssl_ports = [443]
    result = plugin.run_audit("10.0.0.5", [443])

    assert result["status"] == "Vulnerable"
    assert result["severity"] == "CRITICAL"
    assert "CVE-2026-91403" in result["details"]
    assert "Port 443" in result["details"]


def test_run_audit_safe_target(mocker):
    plugin = EmudhraWeakCAAuditPlugin()
    safe_der = generate_self_signed_cert("DigiCert Global Root G2")

    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = safe_der

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock

    mocker.patch("socket.create_connection", return_value=mock_raw_sock)
    mocker.patch("ssl.create_default_context", return_value=mock_ctx)

    plugin.discovered_ssl_ports = [443]
    result = plugin.run_audit("10.0.0.6", [443])

    assert result["status"] == "OK"
    assert "No compromised eMudhra" in result["details"]
