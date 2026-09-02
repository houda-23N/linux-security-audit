import socket


SERVICE_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
}


RISKY_PORTS = {
    21: ("FTP", "HIGH"),
    23: ("Telnet", "HIGH"),
    25: ("SMTP", "MEDIUM"),
    445: ("SMB", "HIGH"),
    1433: ("MSSQL", "HIGH"),
    3306: ("MySQL", "MEDIUM"),
    3389: ("RDP", "HIGH"),
    5432: ("PostgreSQL", "MEDIUM"),
    5900: ("VNC", "HIGH"),
    6379: ("Redis", "HIGH"),
}


def identify_service(port):
    """Return a common service name for a network port."""

    return SERVICE_PORTS.get(port, "Unknown")


def hex_to_ipv4(hex_ip):
    """Convert a hexadecimal IPv4 address to normal notation."""

    try:
        packed = bytes.fromhex(hex_ip)
        return socket.inet_ntoa(packed[::-1])
    except (ValueError, OSError):
        return "Unknown"


def hex_to_ipv6(hex_ip):
    """Convert a hexadecimal IPv6 address to normal notation."""

    try:
        packed = bytes.fromhex(hex_ip)

        if len(packed) != 16:
            return "Unknown"

        return socket.inet_ntop(socket.AF_INET6, packed)

    except (ValueError, OSError):
        return "Unknown"


def parse_proc_file(path, protocol, address_family):
    """Parse a Linux /proc network table."""

    connections = []

    try:
        with open(path, "r") as file:
            lines = file.readlines()[1:]

    except (FileNotFoundError, PermissionError):
        return connections

    for line in lines:
        parts = line.split()

        if len(parts) < 4:
            continue

        local_address = parts[1]
        state = parts[3]

        # TCP state 0A = LISTEN
        # UDP does not use the same LISTEN state.
        if protocol == "TCP" and state != "0A":
            continue

        try:
            ip_hex, port_hex = local_address.split(":")
            port = int(port_hex, 16)

        except (ValueError, IndexError):
            continue

        if address_family == "IPv4":
            address = hex_to_ipv4(ip_hex)
        else:
            address = hex_to_ipv6(ip_hex)

        connections.append({
            "protocol": protocol,
            "family": address_family,
            "address": address,
            "port": port,
            "service": identify_service(port),
        })

    return connections


def get_listening_ports():
    """Return TCP and UDP sockets exposed by the local system."""

    connections = []

    connections.extend(
        parse_proc_file(
            "/proc/net/tcp",
            "TCP",
            "IPv4"
        )
    )

    connections.extend(
        parse_proc_file(
            "/proc/net/tcp6",
            "TCP",
            "IPv6"
        )
    )

    connections.extend(
        parse_proc_file(
            "/proc/net/udp",
            "UDP",
            "IPv4"
        )
    )

    connections.extend(
        parse_proc_file(
            "/proc/net/udp6",
            "UDP",
            "IPv6"
        )
    )

    return connections


def is_publicly_exposed(address, family):
    """Determine whether a socket is bound to a broad interface."""

    if family == "IPv4":
        return address in ("0.0.0.0",)

    if family == "IPv6":
        return address in ("::",)

    return False


def analyze_network_security(connections):
    """Analyze network sockets for potentially risky exposure."""

    findings = []

    for connection in connections:
        port = connection["port"]
        address = connection["address"]
        family = connection["family"]
        protocol = connection["protocol"]

        if port in RISKY_PORTS:
            service, severity = RISKY_PORTS[port]

            if is_publicly_exposed(address, family):
                exposure = "broadly exposed"
            else:
                exposure = "locally bound"

            findings.append({
                "severity": severity,
                "protocol": protocol,
                "port": port,
                "service": service,
                "address": address,
                "issue": (
                    f"{service} is {exposure} "
                    f"on {address}:{port}/{protocol.lower()}."
                )
            })

    return findings
