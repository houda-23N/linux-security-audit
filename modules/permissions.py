import os
import stat
import pwd
import grp

SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh",
]


def get_permission_info(path):
    """Return ownership and permission information for a path."""

    try:
        file_stat = os.stat(path)

    except FileNotFoundError:
        return {
            "path": path,
            "exists": False
        }

    except PermissionError:
        return {
            "path": path,
            "exists": True,
            "error": "Permission denied"
        }
    mode = stat.S_IMODE(file_stat.st_mode)
    owner_name = pwd.getpwuid(file_stat.st_uid).pw_name
    group_name = grp.getgrgid(file_stat.st_gid).gr_name
     
    return {
    "path": path,
    "exists": True,
    "owner_uid": file_stat.st_uid,
    "group_gid": file_stat.st_gid,
    "owner": owner_name,
    "group": group_name,
    "permissions": oct(mode),
    "symbolic_permissions": stat.filemode(file_stat.st_mode),
    "mode": mode,
    "is_directory": stat.S_ISDIR(file_stat.st_mode)
     }

def audit_sensitive_permissions():
    """Collect permissions for important system paths."""

    results = []

    for path in SENSITIVE_PATHS:
        results.append(get_permission_info(path))

    return results

def analyze_permissions(results):
    """Identify potentially dangerous permissions."""

    findings = []

    for result in results:

        if not result.get("exists"):
            findings.append({
                "severity": "INFO",
                "path": result["path"],
                "issue": "Path does not exist."
            })

            continue

        if "error" in result:
            findings.append({
                "severity": "MEDIUM",
                "path": result["path"],
                "issue": result["error"]
            })

            continue

        mode = result["mode"]
        path = result["path"]

        # Check whether anyone other than the owner
        # can write to the file.
        others_write = bool(mode & stat.S_IWOTH)

        if others_write:
            findings.append({
                "severity": "CRITICAL",
                "path": path,
                "issue": (
                    "File is writable by other users."
                )
            })

        # /etc/shadow should not be writable by others.
        if path == "/etc/shadow":

            if mode & stat.S_IWGRP or mode & stat.S_IWOTH:
                findings.append({
                    "severity": "CRITICAL",
                    "path": path,
                    "issue": (
                        "/etc/shadow has excessive "
                        "write permissions."
                    )
                })

    return findings
