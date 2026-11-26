from plugins.nable_ncentral.nable_ncentral_cve_2026_129280_audit import (
    NAbleNCentralAuditPlugin,
    is_ncentral_version_vulnerable,
    parse_ncentral_version,
)


def test_parse_ncentral_version():
    assert parse_ncentral_version("N-central 2026.4.1 HF2") == (2026, 4, 1, 2, "2026.4.1 HF2")
    assert parse_ncentral_version("N-central 2026.4.1.3") == (2026, 4, 1, 3, "2026.4.1 HF3")
    assert parse_ncentral_version("") is None


def test_is_ncentral_version_vulnerable():
    assert is_ncentral_version_vulnerable(2026, 4, 1, 2)[0] is True
    assert is_ncentral_version_vulnerable(2026, 4, 1, 3)[0] is False


def test_ncentral_run_audit(mocker):
    plugin = NAbleNCentralAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-129280"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2026.4.1 HF2",
            "source": "N-central Login",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-129280",
        },
    )
    assert plugin.run_audit("10.0.0.24", [443])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 443,
            "service_detected": True,
            "version": "2026.4.1 HF3",
            "source": "N-central Login",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.24", [443])["status"] == "OK"
