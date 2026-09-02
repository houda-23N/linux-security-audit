import platform
import socket
import getpass
import os
import time


def get_system_info():
    """Collect basic information about the Linux system."""

    info = {
        "Operating System": platform.system(),
        "OS Release": platform.release(),
        "Kernel Version": platform.version(),
        "Hostname": socket.gethostname(),
        "Current User": getpass.getuser(),
        "Architecture": platform.machine(),
        "Python Version": platform.python_version(),
    }

    # Get system uptime
    try:
        with open("/proc/uptime", "r") as file:
            uptime_seconds = float(file.readline().split()[0])

        uptime_hours = uptime_seconds / 3600
        info["System Uptime"] = f"{uptime_hours:.2f} hours"

    except Exception:
        info["System Uptime"] = "Unavailable"

    return info
