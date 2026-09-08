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


def get_groups():
    """Return local group information from /etc/group."""

    groups = []

    try:
        with open("/etc/group", "r") as file:
            for line in file:
                parts = line.strip().split(":")

                if len(parts) >= 4:
                    group_name = parts[0]
                    members = [
                        user
                        for user in parts[3].split(",")
                        if user
                    ]

                    groups.append({
                        "name": group_name,
                        "members": members
                    })

    except PermissionError:
        return []

    return groups


def get_privileged_users_from_groups(groups):
    """Identify users belonging to privileged groups."""

    privileged_users = []

    privileged_groups = {
        "sudo",
        "adm"
    }

    for group in groups:
        group_name = group.get("name", "")
        members = group.get("members", [])

        if group_name in privileged_groups:
            for user in members:
                if user and user not in privileged_users:
                    privileged_users.append(user)

    return privileged_users


def get_privileged_users(users):
    """Identify users with administrative privileges."""

    groups = get_groups()

    return get_privileged_users_from_groups(groups)


    return groups


def get_privileged_users_from_groups(groups):
    """Identify users belonging to privileged groups."""

    privileged_users = []

    privileged_groups = {
        "sudo",
        "adm"
    }

    for group in groups:
        group_name = group.get("name", "")
        members = group.get("members", [])

        if group_name in privileged_groups:
            for user in members:
                if user and user not in privileged_users:
                    privileged_users.append(user)

    return privileged_users


def get_privileged_users(users):
    """Identify users with administrative privileges."""

    groups = get_groups()

    return get_privileged_users_from_groups(groups)
