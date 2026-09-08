from modules.services import analyze_services


def test_telnet_service_detection():
    services = [
        {
            "name": "telnet.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "enabled": True,
            "description": "Telnet service"
        }
    ]

    findings = analyze_services(services)

    assert len(findings) == 1
    assert findings[0]["service"] == "Telnet"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["issue"] == (
        "Telnet service is currently running."
    )


def test_mysql_service_detection():
    services = [
        {
            "name": "mysql.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "enabled": True,
            "description": "MySQL database server"
        }
    ]

    findings = analyze_services(services)

    assert len(findings) == 1
    assert findings[0]["service"] == "MySQL"
    assert findings[0]["severity"] == "MEDIUM"


def test_cups_service_detection():
    services = [
        {
            "name": "cups.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "enabled": True,
            "description": "CUPS printing service"
        }
    ]

    findings = analyze_services(services)

    assert len(findings) == 1
    assert findings[0]["service"] == "CUPS printing"
    assert findings[0]["severity"] == "LOW"


def test_safe_service_is_not_flagged():
    services = [
        {
            "name": "systemd-journald.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "enabled": True,
            "description": "Journal Service"
        }
    ]

    findings = analyze_services(services)

    assert findings == []


def test_multiple_services_are_detected():
    services = [
        {
            "name": "telnet.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "enabled": True,
            "description": "Telnet service"
        },
        {
            "name": "mysql.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "enabled": True,
            "description": "MySQL database server"
        }
    ]

    findings = analyze_services(services)

    assert len(findings) == 2

    assert findings[0]["service"] == "Telnet"
    assert findings[0]["severity"] == "HIGH"

    assert findings[1]["service"] == "MySQL"
    assert findings[1]["severity"] == "MEDIUM"

