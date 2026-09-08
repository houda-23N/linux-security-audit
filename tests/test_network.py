from modules.network import (
    identify_service,
    is_publicly_exposed,
    analyze_network_security
)


def test_identify_known_service():
    result = identify_service(22)

    assert result == "SSH"


def test_identify_unknown_service():
    result = identify_service(9999)

    assert result == "Unknown"


def test_ipv4_public_exposure():
    result = is_publicly_exposed(
        "0.0.0.0",
        "IPv4"
    )

    assert result is True


def test_ipv4_local_binding():
    result = is_publicly_exposed(
        "127.0.0.1",
        "IPv4"
    )

    assert result is False


def test_ipv6_public_exposure():
    result = is_publicly_exposed(
        "::",
        "IPv6"
    )

    assert result is True


def test_safe_port_is_not_flagged():
    connections = [
        {
            "protocol": "TCP",
            "family": "IPv4",
            "address": "0.0.0.0",
            "port": 22,
            "service": "SSH"
        }
    ]

    findings = analyze_network_security(connections)

    assert findings == []


def test_risky_public_port_is_detected():
    connections = [
        {
            "protocol": "TCP",
            "family": "IPv4",
            "address": "0.0.0.0",
            "port": 23,
            "service": "Telnet"
        }
    ]

    findings = analyze_network_security(connections)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["service"] == "Telnet"
    assert findings[0]["port"] == 23
    assert "broadly exposed" in findings[0]["issue"]


def test_risky_local_port_is_detected():
    connections = [
        {
            "protocol": "TCP",
            "family": "IPv4",
            "address": "127.0.0.1",
            "port": 3306,
            "service": "MySQL"
        }
    ]

    findings = analyze_network_security(connections)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["service"] == "MySQL"
    assert findings[0]["port"] == 3306
    assert "locally bound" in findings[0]["issue"]


def test_multiple_risky_ports_are_detected():
    connections = [
        {
            "protocol": "TCP",
            "family": "IPv4",
            "address": "0.0.0.0",
            "port": 23,
            "service": "Telnet"
        },
        {
            "protocol": "TCP",
            "family": "IPv4",
            "address": "0.0.0.0",
            "port": 445,
            "service": "SMB"
        }
    ]

    findings = analyze_network_security(connections)

    assert len(findings) == 2

    assert findings[0]["service"] == "Telnet"
    assert findings[0]["severity"] == "HIGH"

    assert findings[1]["service"] == "SMB"
    assert findings[1]["severity"] == "HIGH"
