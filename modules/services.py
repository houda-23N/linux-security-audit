import subprocess

def get_service_enabled_status(service_name):
    """Check whether a systemd service is enabled at boot."""

    try:
        result = subprocess.run(
            [
                "systemctl",
                "is-enabled",
                service_name
            ],
            capture_output=True,
            text=True,
            check=False
        )

        status = result.stdout.strip()

        if status == "enabled":
            return True

        return False

    except FileNotFoundError:
        return False

def get_running_services():
    """Return systemd services that are currently running."""

    services = []

    try:
        result = subprocess.run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager"
            ],
            capture_output=True,
            text=True,
            check=False
        )

        for line in result.stdout.splitlines():
            parts = line.split()

            if len(parts) < 4:
                continue

            service_name = parts[0]
            load_state = parts[1]
            active_state = parts[2]
            sub_state = parts[3]
            description = " ".join(parts[4:])

            enabled = get_service_enabled_status(service_name)

            services.append({
                "name": service_name,
                "load": load_state,
                "active": active_state,
                "sub": sub_state,
                "enabled": enabled,
                "description": description
            })

    except FileNotFoundError:
        return []

    return services

def analyze_services(services):
    """Identify services that may deserve additional security review."""

    findings = []

    services_to_review = {
        "telnet.service": ("Telnet", "HIGH"),
        "vsftpd.service": ("FTP", "HIGH"),
        "smbd.service": ("SMB", "HIGH"),
        "nmbd.service": ("NetBIOS", "HIGH"),
        "redis-server.service": ("Redis", "HIGH"),
        "mysql.service": ("MySQL", "MEDIUM"),
        "postgresql.service": ("PostgreSQL", "MEDIUM"),
        "cups.service": ("CUPS printing", "LOW"),
    }

    for service in services:
        name = service["name"]

        if name in services_to_review:
            service_name, severity = services_to_review[name]

            findings.append({
                "service": service_name,
                "severity": severity,
                "issue": (
                    f"{service_name} service is currently running."
                )
            })

    return findings

