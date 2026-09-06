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
            "issue": "SSH server configuration was not found.",
            "evidence": (
                "The SSH server configuration file "
                "/etc/ssh/sshd_config was not found."
            ),
            "impact": (
                "SSH server security settings could not be "
                "evaluated because no server configuration "
                "was detected."
            ),
            "recommendation": (
                "If SSH server access is required, verify that "
                "the SSH server is installed and configured "
                "according to your security requirements."
            )
        })

        return findings

    settings = config["settings"]

    # Check root login
    root_login = settings.get(
        "PermitRootLogin",
        ""
    ).lower()

    if root_login in [
        "yes",
        "without-password",
        "prohibit-password"
    ]:
        findings.append({
            "severity": "HIGH",
            "issue": (
                f"Root SSH login setting: {root_login}"
            ),
            "evidence": (
                "The PermitRootLogin setting was detected as: "
                f"{root_login}"
            ),
            "impact": (
                "Allowing direct root login over SSH increases "
                "the risk associated with compromised "
                "administrator credentials."
            ),
            "recommendation": (
                "Disable direct root SSH login where possible "
                "and use a standard user account with "
                "controlled privilege escalation."
            )
        })

    # Check password authentication
    password_auth = settings.get(
        "PasswordAuthentication",
        "yes"
    ).lower()

    if password_auth == "yes":
        findings.append({
            "severity": "MEDIUM",
            "issue": (
                "Password authentication is enabled."
            ),
            "evidence": (
                "SSH configuration allows password-based "
                "authentication."
            ),
            "impact": (
                "Password-based SSH authentication may be more "
                "susceptible to password guessing and "
                "brute-force attacks."
            ),
            "recommendation": (
                "Consider disabling SSH password authentication "
                "after confirming that secure public-key "
                "authentication is configured and tested."
            )
        })

    # Check empty passwords
    empty_passwords = settings.get(
        "PermitEmptyPasswords",
        "no"
    ).lower()

    if empty_passwords == "yes":
        findings.append({
            "severity": "CRITICAL",
            "issue": (
                "Empty passwords are permitted for SSH."
            ),
            "evidence": (
                "The PermitEmptyPasswords setting was detected "
                "as enabled."
            ),
            "impact": (
                "Allowing empty passwords can enable "
                "unauthorized access to accounts that do not "
                "have a password configured."
            ),
            "recommendation": (
                "Set PermitEmptyPasswords to no and verify that "
                "all SSH-accessible accounts use strong "
                "authentication."
            )
        })

    return findings
