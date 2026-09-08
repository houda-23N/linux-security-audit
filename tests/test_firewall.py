from modules.firewall import analyze_firewall


def test_firewall_not_installed():
    firewall = {
        "installed": False,
        "active": False,
        "status": "UFW not installed",
        "default_incoming": None,
        "default_outgoing": None,
        "rules": []
    }

    findings = analyze_firewall(firewall)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["issue"] == (
        "UFW firewall is not installed."
    )


def test_firewall_inactive():
    firewall = {
        "installed": True,
        "active": False,
        "status": "inactive",
        "default_incoming": None,
        "default_outgoing": None,
        "rules": []
    }

    findings = analyze_firewall(firewall)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["issue"] == (
        "UFW firewall is inactive."
    )


def test_firewall_active_with_deny_policy():
    firewall = {
        "installed": True,
        "active": True,
        "status": "active",
        "default_incoming": "deny",
        "default_outgoing": "allow",
        "rules": []
    }

    findings = analyze_firewall(firewall)

    assert len(findings) == 2

    assert findings[0]["severity"] == "INFO"
    assert findings[0]["issue"] == (
        "UFW firewall is active."
    )

    assert findings[1]["severity"] == "INFO"
    assert findings[1]["issue"] == (
        "Default incoming firewall policy is set to deny."
    )


def test_firewall_allows_incoming_connections():
    firewall = {
        "installed": True,
        "active": True,
        "status": "active",
        "default_incoming": "allow",
        "default_outgoing": "allow",
        "rules": []
    }

    findings = analyze_firewall(firewall)

    assert len(findings) == 2

    assert findings[0]["severity"] == "INFO"
    assert findings[0]["issue"] == (
        "UFW firewall is active."
    )

    assert findings[1]["severity"] == "HIGH"
    assert findings[1]["issue"] == (
        "Default incoming firewall policy is set to allow."
    )


def test_firewall_active_without_known_incoming_policy():
    firewall = {
        "installed": True,
        "active": True,
        "status": "active",
        "default_incoming": None,
        "default_outgoing": None,
        "rules": []
    }

    findings = analyze_firewall(firewall)

    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["issue"] == (
        "UFW firewall is active."
    )
