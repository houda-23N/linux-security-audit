import subprocess

def get_recent_security_logs(lines=200):
    """Collect recent authentication-related log entries."""

    try:
        result = subprocess.run(
            [
                "journalctl",
                "--no-pager",
                "-n",
                str(lines)
            ],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            return result.stdout.splitlines()

    except FileNotFoundError:
        pass

    # Fallback for systems using /var/log/auth.log
    try:
        with open("/var/log/auth.log", "r") as file:
            return file.readlines()[-lines:]

    except (FileNotFoundError, PermissionError):
        return []


def analyze_security_logs(logs):
    """Analyze logs for authentication-related security events."""

    findings = []

    failed_password = 0
    invalid_user = 0
    authentication_failure = 0
    accepted_password = 0
    accepted_publickey = 0

    for line in logs:

        if "Failed password" in line:
            failed_password += 1

        if "Invalid user" in line:
            invalid_user += 1

        if "authentication failure" in line.lower():
            authentication_failure += 1

        if "Accepted password" in line:
            accepted_password += 1

        if "Accepted publickey" in line:
            accepted_publickey += 1

    if failed_password > 0:
        findings.append({
            "severity": "MEDIUM",
            "type": "Failed SSH authentication",
            "count": failed_password,
            "issue": (
                f"{failed_password} failed SSH password "
                "authentication attempt(s) detected."
            )
        })

    if invalid_user > 0:
        findings.append({
            "severity": "MEDIUM",
            "type": "Invalid user attempts",
            "count": invalid_user,
            "issue": (
                f"{invalid_user} SSH attempt(s) used "
                "an invalid username."
            )
        })

    if authentication_failure > 0:
        findings.append({
            "severity": "MEDIUM",
            "type": "Authentication failure",
            "count": authentication_failure,
            "issue": (
                f"{authentication_failure} authentication "
                "failure event(s) detected."
            )
        })

    if accepted_password > 0:
        findings.append({
            "severity": "INFO",
            "type": "Successful password login",
            "count": accepted_password,
            "issue": (
                f"{accepted_password} successful SSH password "
                "login(s) detected."
            )
        })

    if accepted_publickey > 0:
        findings.append({
            "severity": "INFO",
            "type": "Successful key login",
            "count": accepted_publickey,
            "issue": (
                f"{accepted_publickey} successful SSH public-key "
                "login(s) detected."
            )
        })

    return findings


def get_log_summary(logs):
    """Return basic statistics about collected logs."""

    return {
        "total_lines": len(logs),
        "failed_password": sum(
            1 for line in logs
            if "Failed password" in line
        ),
        "invalid_user": sum(
            1 for line in logs
            if "Invalid user" in line
        ),
        "authentication_failure": sum(
            1 for line in logs
            if "authentication failure" in line.lower()
        ),
        "successful_password": sum(
            1 for line in logs
            if "Accepted password" in line
        ),
        "successful_publickey": sum(
            1 for line in logs
            if "Accepted publickey" in line
        )
    }
