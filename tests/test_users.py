from unittest.mock import mock_open, patch

from modules.users import (
    get_users,
    get_groups,
    get_privileged_users_from_groups
)


def test_sudo_users_are_detected():
    groups = [
        {
            "name": "sudo",
            "members": ["alice", "bob"]
        }
    ]

    privileged = get_privileged_users_from_groups(groups)

    assert privileged == ["alice", "bob"]


def test_adm_users_are_detected():
    groups = [
        {
            "name": "adm",
            "members": ["alice"]
        }
    ]

    privileged = get_privileged_users_from_groups(groups)

    assert privileged == ["alice"]


def test_normal_groups_are_not_flagged():
    groups = [
        {
            "name": "users",
            "members": ["alice", "bob"]
        }
    ]

    privileged = get_privileged_users_from_groups(groups)

    assert privileged == []


def test_multiple_privileged_groups():
    groups = [
        {
            "name": "sudo",
            "members": ["alice"]
        },
        {
            "name": "adm",
            "members": ["bob"]
        }
    ]

    privileged = get_privileged_users_from_groups(groups)

    assert privileged == ["alice", "bob"]


def test_duplicate_privileged_users_are_removed():
    groups = [
        {
            "name": "sudo",
            "members": ["alice", "bob"]
        },
        {
            "name": "adm",
            "members": ["alice"]
        }
    ]

    privileged = get_privileged_users_from_groups(groups)

    assert privileged == ["alice", "bob"]


def test_empty_groups():
    groups = []

    privileged = get_privileged_users_from_groups(groups)

    assert privileged == []


def test_empty_group_members():
    groups = [
        {
            "name": "sudo",
            "members": []
        }
    ]

    privileged = get_privileged_users_from_groups(groups)

    assert privileged == []


def test_get_groups_parses_group_file():
    fake_group_file = (
        "root:x:0:\n"
        "sudo:x:27:alice,bob\n"
        "adm:x:4:alice\n"
        "users:x:100:alice,bob\n"
    )

    with patch(
        "builtins.open",
        mock_open(read_data=fake_group_file)
    ):
        groups = get_groups()

    assert groups == [
        {
            "name": "root",
            "members": []
        },
        {
            "name": "sudo",
            "members": ["alice", "bob"]
        },
        {
            "name": "adm",
            "members": ["alice"]
        },
        {
            "name": "users",
            "members": ["alice", "bob"]
        }
    ]


def test_get_groups_handles_empty_file():
    with patch(
        "builtins.open",
        mock_open(read_data="")
    ):
        groups = get_groups()

    assert groups == []


def test_get_groups_ignores_malformed_lines():
    fake_group_file = (
        "sudo:x:27:alice\n"
        "malformed line\n"
        "adm:x:4:bob\n"
    )

    with patch(
        "builtins.open",
        mock_open(read_data=fake_group_file)
    ):
        groups = get_groups()

    assert groups == [
        {
            "name": "sudo",
            "members": ["alice"]
        },
        {
            "name": "adm",
            "members": ["bob"]
        }
    ]


def test_get_groups_handles_permission_error():
    with patch(
        "builtins.open",
        side_effect=PermissionError
    ):
        groups = get_groups()

    assert groups == []

def test_get_users_parses_passwd_file():
    fake_passwd_file = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n"
    )

    with patch(
        "builtins.open",
        mock_open(read_data=fake_passwd_file)
    ):
        users = get_users()

    assert users == [
        {
            "username": "root",
            "home": "/root",
            "shell": "/bin/bash"
        },
        {
            "username": "alice",
            "home": "/home/alice",
            "shell": "/bin/bash"
        },
        {
            "username": "bob",
            "home": "/home/bob",
            "shell": "/bin/zsh"
        }
    ]


def test_get_users_handles_empty_file():
    with patch(
        "builtins.open",
        mock_open(read_data="")
    ):
        users = get_users()

    assert users == []


def test_get_users_ignores_malformed_lines():
    fake_passwd_file = (
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
        "malformed line\n"
        "bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n"
    )

    with patch(
        "builtins.open",
        mock_open(read_data=fake_passwd_file)
    ):
        users = get_users()

    assert users == [
        {
            "username": "alice",
            "home": "/home/alice",
            "shell": "/bin/bash"
        },
        {
            "username": "bob",
            "home": "/home/bob",
            "shell": "/bin/zsh"
        }
    ]


def test_get_users_handles_permission_error():
    with patch(
        "builtins.open",
        side_effect=PermissionError
    ):
        users = get_users()

    assert users == []


def test_get_users_extracts_home_and_shell():
    fake_passwd_file = (
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    )

    with patch(
        "builtins.open",
        mock_open(read_data=fake_passwd_file)
    ):
        users = get_users()

    assert len(users) == 1
    assert users[0]["username"] == "alice"
    assert users[0]["home"] == "/home/alice"
    assert users[0]["shell"] == "/bin/bash"
