def get_users():
    """Return a list of local users on the system."""

    users = []

    try:
        with open("/etc/passwd", "r") as file:
            for line in file:
                parts = line.strip().split(":")

                if len(parts) >= 7:
                    username = parts[0]
                    home_directory = parts[5]
                    shell = parts[6]

                    users.append({
                        "username": username,
                        "home": home_directory,
                        "shell": shell
                    })

    except PermissionError:
        return []

    return users

def get_privileged_users(users):
    """Identify users with administrative privileges."""

    privileged_users = []

    try:
        with open("/etc/group", "r") as file:
            for line in file:
                parts = line.strip().split(":")

                if len(parts) >= 4:
                    group_name = parts[0]
                    members = parts[3].split(",")

                    if group_name in ["sudo", "adm"]:
                        for user in members:
                            if user and user not in privileged_users:
                                privileged_users.append(user)

    except PermissionError:
        return []

    return privileged_users
