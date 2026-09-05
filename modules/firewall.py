import subprocess

def get_ufw_status():
    """Check the current UFW firewall status and rules."""

    try:
        result = subprocess.run(
            ["sudo", "ufw", "status", "verbose"],
            capture_output=True,
            text=True,
            check=False
        )

    except FileNotFoundError:
        return {
            "installed": False,
            "active": False,
            "status": "UFW not installed",
            "default_incoming": None,
            "default_outgoing": None,
            "rules": []
        }

    output = result.stdout

    if "Status: active" in output:
        active = True
        status = "active"

    elif "Status: inactive" in output:
        active = False
        status = "inactive"

    else:
        active = False
        status = "unknown"

    default_incoming = None
    default_outgoing = None

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Default:"):
            parts = line.split()

            for index, part in enumerate(parts):
                if part == "incoming" and index > 0:
                    default_incoming = parts[index - 1]

                if part == "outgoing" and index > 0:
                    default_outgoing = parts[index - 1]

    rules = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("To"):
            continue

        if line.startswith("--"):
            continue

        if (
            "ALLOW" in line
            or "DENY" in line
            or "REJECT" in line
        ):
            rules.append(line)

    return {
        "installed": True,
        "active": active,
        "status": status,
        "default_incoming": default_incoming,
        "default_outgoing": default_outgoing,
        "rules": rules,
        "raw_output": output
    }

def analyze_firewall(firewall):
    """Analyze firewall configuration for security issues."""

    findings = []

    if not firewall["installed"]:
        findings.append({
            "severity": "MEDIUM",
            "issue": "UFW firewall is not installed."
        })

        return findings

    if not firewall["active"]:
        findings.append({
            "severity": "HIGH",
            "issue": "UFW firewall is inactive."
        })

        return findings

    findings.append({
        "severity": "INFO",
        "issue": "UFW firewall is active."
    })

    incoming = firewall["default_incoming"]

    if incoming == "allow":
        findings.append({
            "severity": "HIGH",
            "issue": (
                "Default incoming firewall policy "
                "is set to allow."
            )
        })

    elif incoming == "deny":
        findings.append({
            "severity": "INFO",
            "issue": (
                "Default incoming firewall policy "
                "is set to deny."
            )
        })

    return findings
