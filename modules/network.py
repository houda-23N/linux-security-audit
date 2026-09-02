import socket


def get_listening_ports():
    """Identify TCP ports currently listening on the local system."""

    listening_ports = []

    try:
        with open("/proc/net/tcp", "r") as file:
            lines = file.readlines()[1:]

        for line in lines:
            parts = line.split()

            if len(parts) < 4:
                continue

            local_address = parts[1]
            state = parts[3]

            # TCP state 0A means LISTEN
            if state != "0A":
                continue

            ip_hex, port_hex = local_address.split(":")

            port = int(port_hex, 16)

            listening_ports.append({
                "protocol": "TCP",
                "port": port
            })

    except (FileNotFoundError, PermissionError):
        return []

    return listening_ports

def identify_service(port):
    """Try to identify the common service associated with a port."""

    common_services = {
        20: "FTP-data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-alt"
    }

    return common_services.get(port, "Unknown")

def analyze_network_security(ports):
    """Analyze listening ports for potentially risky services."""

    findings = []

    risky_ports = {
        21: ("FTP", "HIGH"),
        23: ("Telnet", "HIGH"),
        25: ("SMTP", "MEDIUM"),
        3306: ("MySQL", "MEDIUM"),
        5432: ("PostgreSQL", "MEDIUM"),
        6379: ("Redis", "HIGH")
    }

    for entry in ports:
        port = entry["port"]

        if port in risky_ports:
            service, severity = risky_ports[port]

            findings.append({
                "port": port,
                "service": service,
                "severity": severity,
                "issue": f"{service} is listening on port {port}."
            })

    return findings
