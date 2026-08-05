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


# Content types the runner inlines as text — and therefore the only ones the
# prompt-injection screen inspects (runtime/runner._load_file_content). Anything
# else goes to the model as opaque BinaryContent, unscreened, which is why the
# upload path derives the type from the bytes instead of trusting the client
# (api/v1/files.sniff_content_type).
TEXT_CONTENT_TYPES = ("text/", "application/json", "application/xml", "application/csv")
