from enum import StrEnum


class Role(StrEnum):
    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"


# Ordered for "role >= required" checks.
ROLE_RANK = {Role.VIEWER: 0, Role.EDITOR: 1, Role.OWNER: 2}


class KeyKind(StrEnum):
    USER = "user"
    INVOKE = "invoke"


class KeyScope(StrEnum):
    TENANT = "tenant"
    TEAM = "team"
    AGENT = "agent"
