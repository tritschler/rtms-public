from plugins.arangodb.arangodb_cve_2026_126755_audit import (
    ArangoDBAuditPlugin,
    is_arangodb_version_vulnerable,
    parse_arangodb_version,
)


def test_parse_arangodb_version():
    assert parse_arangodb_version("ArangoDB 3.12.10") == (3, 12, 10, "3.12.10")
    assert parse_arangodb_version("ArangoDB/3.12.11") == (3, 12, 11, "3.12.11")
    assert parse_arangodb_version("") is None


def test_is_arangodb_version_vulnerable():
    assert is_arangodb_version_vulnerable(3, 12, 10)[0] is True
    assert is_arangodb_version_vulnerable(3, 12, 11)[0] is False


def test_arangodb_run_audit(mocker):
    plugin = ArangoDBAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-126755"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8529,
            "service_detected": True,
            "version": "3.12.9",
            "source": "ArangoDB API",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-126755",
        },
    )
    assert plugin.run_audit("10.0.0.23", [8529])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 8529,
            "service_detected": True,
            "version": "3.12.11",
            "source": "ArangoDB API",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.23", [8529])["status"] == "OK"
