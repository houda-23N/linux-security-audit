import os
import re


def get_ssh_config_path():
    """Return the path to the SSH server configuration file."""

    config_path = "/etc/ssh/sshd_config"

    if os.path.exists(config_path):
        return config_path

    return None


def read_ssh_config():
    """Read the SSH server configuration."""

    config_path = get_ssh_config_path()

    if not config_path:
        return {
            "installed": False,
            "config_path": None,
            "settings": {}
        }

    settings = {}

    try:
        with open(config_path, "r") as file:
            for line in file:
                line = line.strip()

                # Ignore comments and empty lines
                if not line or line.startswith("#"):
                    continue

                parts = line.split(None, 1)

                if len(parts) == 2:
                    key = parts[0]
                    value = parts[1]

                    settings[key] = value

    except PermissionError:
        return {
            "installed": True,
            "config_path": config_path,
            "settings": {},
            "error": "Permission denied"
        }

    return {
        "installed": True,
        "config_path": config_path,
        "settings": settings
    }

def analyze_ssh_security(config):
    """Analyze SSH configuration for potentially insecure settings."""

    findings = []

    if not config["installed"]:
        findings.append({
            "severity": "INFO",
            "issue": "SSH server configuration was not found."
        })

        return findings

    settings = config["settings"]

    # Check root login
    root_login = settings.get("PermitRootLogin", "").lower()

    if root_login in ["yes", "without-password", "prohibit-password"]:
        findings.append({
            "severity": "HIGH",
            "issue": f"Root SSH login setting: {root_login}"
        })

    # Check password authentication
    password_auth = settings.get(
        "PasswordAuthentication",
        "yes"
    ).lower()

    if password_auth == "yes":
        findings.append({
            "severity": "MEDIUM",
            "issue": "Password authentication is enabled."
        })

    # Check empty passwords
    empty_passwords = settings.get(
        "PermitEmptyPasswords",
        "no"
    ).lower()

    if empty_passwords == "yes":
        findings.append({
            "severity": "CRITICAL",
            "issue": "Empty passwords are permitted for SSH."
        })

    return findings
