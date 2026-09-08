from modules.logs import (
    analyze_security_logs,
    get_log_summary
)


def test_failed_password_detection():
    logs = [
        "Sep 08 10:00:00 host sshd[100]: Failed password for user admin",
        "Sep 08 10:01:00 host sshd[101]: Failed password for user test"
    ]

    findings = analyze_security_logs(logs)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["type"] == "Failed SSH authentication"
    assert findings[0]["count"] == 2


def test_invalid_user_detection():
    logs = [
        "Sep 08 10:00:00 host sshd[100]: Invalid user hacker",
        "Sep 08 10:01:00 host sshd[101]: Invalid user admin"
    ]

    findings = analyze_security_logs(logs)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["type"] == "Invalid user attempts"
    assert findings[0]["count"] == 2


def test_authentication_failure_detection():
    logs = [
        "Sep 08 10:00:00 host sshd: authentication failure",
        "Sep 08 10:01:00 host sshd: Authentication Failure"
    ]

    findings = analyze_security_logs(logs)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["type"] == "Authentication failure"
    assert findings[0]["count"] == 2


def test_successful_password_login_detection():
    logs = [
        "Sep 08 10:00:00 host sshd[100]: Accepted password for user admin"
    ]

    findings = analyze_security_logs(logs)

    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["type"] == "Successful password login"
    assert findings[0]["count"] == 1


def test_successful_public_key_login_detection():
    logs = [
        "Sep 08 10:00:00 host sshd[100]: Accepted publickey for user admin"
    ]

    findings = analyze_security_logs(logs)

    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["type"] == "Successful key login"
    assert findings[0]["count"] == 1


def test_clean_logs_produce_no_findings():
    logs = [
        "Sep 08 10:00:00 host systemd: Started system service",
        "Sep 08 10:01:00 host systemd: Service completed successfully"
    ]

    findings = analyze_security_logs(logs)

    assert findings == []


def test_log_summary_counts_events():
    logs = [
        "Failed password for user admin",
        "Failed password for user test",
        "Invalid user hacker",
        "authentication failure",
        "Accepted password for user admin",
        "Accepted publickey for user alice"
    ]

    summary = get_log_summary(logs)

    assert summary["total_lines"] == 6
    assert summary["failed_password"] == 2
    assert summary["invalid_user"] == 1
    assert summary["authentication_failure"] == 1
    assert summary["successful_password"] == 1
    assert summary["successful_publickey"] == 1


def test_empty_logs():
    logs = []

    findings = analyze_security_logs(logs)
    summary = get_log_summary(logs)

    assert findings == []

    assert summary["total_lines"] == 0
    assert summary["failed_password"] == 0
    assert summary["invalid_user"] == 0
    assert summary["authentication_failure"] == 0
    assert summary["successful_password"] == 0
    assert summary["successful_publickey"] == 0
