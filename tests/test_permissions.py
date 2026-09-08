from modules.permissions import analyze_permissions


def test_missing_path_is_reported():
    results = [
        {
            "path": "/etc/example-missing",
            "exists": False
        }
    ]

    findings = analyze_permissions(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "INFO"
    assert findings[0]["path"] == "/etc/example-missing"
    assert findings[0]["issue"] == "Path does not exist."


def test_permission_denied_is_reported():
    results = [
        {
            "path": "/etc/shadow",
            "exists": True,
            "error": "Permission denied"
        }
    ]

    findings = analyze_permissions(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["path"] == "/etc/shadow"
    assert findings[0]["issue"] == "Permission denied"


def test_world_writable_file_is_critical():
    results = [
        {
            "path": "/etc/passwd",
            "exists": True,
            "owner": "root",
            "group": "root",
            "permissions": "0o666",
            "symbolic_permissions": "-rw-rw-rw-",
            "mode": 0o666,
            "is_directory": False
        }
    ]

    findings = analyze_permissions(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["path"] == "/etc/passwd"
    assert findings[0]["issue"] == (
        "File is writable by other users."
    )


def test_secure_passwd_permissions_are_not_flagged():
    results = [
        {
            "path": "/etc/passwd",
            "exists": True,
            "owner": "root",
            "group": "root",
            "permissions": "0o644",
            "symbolic_permissions": "-rw-r--r--",
            "mode": 0o644,
            "is_directory": False
        }
    ]

    findings = analyze_permissions(results)

    assert findings == []


def test_shadow_excessive_write_permissions_are_critical():
    results = [
        {
            "path": "/etc/shadow",
            "exists": True,
            "owner": "root",
            "group": "shadow",
            "permissions": "0o662",
            "symbolic_permissions": "-rw-rw--w-",
            "mode": 0o662,
            "is_directory": False
        }
    ]

    findings = analyze_permissions(results)

    assert len(findings) == 2

    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["path"] == "/etc/shadow"
    assert findings[0]["issue"] == (
        "File is writable by other users."
    )

    assert findings[1]["severity"] == "CRITICAL"
    assert findings[1]["path"] == "/etc/shadow"
    assert findings[1]["issue"] == (
        "/etc/shadow has excessive write permissions."
    )


def test_secure_shadow_permissions_are_not_flagged():
    results = [
        {
            "path": "/etc/shadow",
            "exists": True,
            "owner": "root",
            "group": "shadow",
            "permissions": "0o640",
            "symbolic_permissions": "-rw-r-----",
            "mode": 0o640,
            "is_directory": False
        }
    ]

    findings = analyze_permissions(results)

    assert findings == []


def test_multiple_permission_findings_are_detected():
    results = [
        {
            "path": "/etc/passwd",
            "exists": True,
            "owner": "root",
            "group": "root",
            "permissions": "0o666",
            "symbolic_permissions": "-rw-rw-rw-",
            "mode": 0o666,
            "is_directory": False
        },
        {
            "path": "/etc/sudoers",
            "exists": True,
            "owner": "root",
            "group": "root",
            "permissions": "0o440",
            "symbolic_permissions": "-r--r-----",
            "mode": 0o440,
            "is_directory": False
        }
    ]

    findings = analyze_permissions(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["path"] == "/etc/passwd"
