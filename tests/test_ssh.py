from modules.ssh import analyze_ssh_security


def test_ssh_not_installed():
    config = {
        "installed": False,
        "config_path": None,
        "settings": {}
    }

    findings = analyze_ssh_security(config)

    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert (
        findings[0]["issue"]
        == "SSH server configuration was not found."
    )


def test_password_authentication_enabled():
    config = {
        "installed": True,
        "config_path": "/etc/ssh/sshd_config",
        "settings": {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "yes",
            "PermitEmptyPasswords": "no"
        }
    }

    findings = analyze_ssh_security(config)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert (
        findings[0]["issue"]
        == "Password authentication is enabled."
    )


def test_empty_passwords_allowed():
    config = {
        "installed": True,
        "config_path": "/etc/ssh/sshd_config",
        "settings": {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PermitEmptyPasswords": "yes"
        }
    }

    findings = analyze_ssh_security(config)

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert (
        findings[0]["issue"]
        == "Empty passwords are permitted for SSH."
    )


def test_root_ssh_login_enabled():
    config = {
        "installed": True,
        "config_path": "/etc/ssh/sshd_config",
        "settings": {
            "PermitRootLogin": "yes",
            "PasswordAuthentication": "no",
            "PermitEmptyPasswords": "no"
        }
    }

    findings = analyze_ssh_security(config)

    assert len(findings) == 1

    assert findings[0]["severity"] == "HIGH"
    assert (
        findings[0]["issue"]
        == "Root SSH login setting: yes"
    )


def test_secure_ssh_configuration():
    config = {
        "installed": True,
        "config_path": "/etc/ssh/sshd_config",
        "settings": {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PermitEmptyPasswords": "no"
        }
    }

    findings = analyze_ssh_security(config)

    assert findings == []
