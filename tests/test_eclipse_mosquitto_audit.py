from plugins.eclipse_mosquitto.eclipse_mosquitto_cve_2026_110486_audit import (
    EclipseMosquittoAuditPlugin,
    is_mosquitto_version_vulnerable,
    parse_mosquitto_version,
)


def test_parse_mosquitto_version():
    assert parse_mosquitto_version("mosquitto version 2.1.2") == (2, 1, 2, "2.1.2")
    assert parse_mosquitto_version("mosquitto 2.1.3") == (2, 1, 3, "2.1.3")
    assert parse_mosquitto_version("") is None


def test_is_mosquitto_version_vulnerable():
    assert is_mosquitto_version_vulnerable(2, 1, 0)[0] is True
    assert is_mosquitto_version_vulnerable(2, 1, 2)[0] is True
    assert is_mosquitto_version_vulnerable(2, 1, 3)[0] is False
    assert is_mosquitto_version_vulnerable(2, 0, 20)[0] is False


def test_mosquitto_run_audit(mocker):
    plugin = EclipseMosquittoAuditPlugin()
    assert plugin.info["cve"] == "CVE-2026-110486"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 1883,
            "service_detected": True,
            "version": "2.1.1",
            "source": "Mosquitto Banner",
            "is_vulnerable": True,
            "reason": "Affected by CVE-2026-110486",
        },
    )
    assert plugin.run_audit("10.0.0.18", [1883])["status"] == "Vulnerable"

    mocker.patch.object(
        plugin,
        "inspect_target_port",
        return_value={
            "port": 1883,
            "service_detected": True,
            "version": "2.1.3",
            "source": "Mosquitto Banner",
            "is_vulnerable": False,
            "reason": "Patched",
        },
    )
    assert plugin.run_audit("10.0.0.18", [1883])["status"] == "OK"
