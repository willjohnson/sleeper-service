"""Validation for server-initiated HTTP destinations."""

import ipaddress
import socket
from urllib.parse import urlparse

import anyio

from sleeper_service.config import get_settings
from sleeper_service.runtime.links import host_allowed


class OutboundUrlError(ValueError):
    pass


def _address_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_loopback: bool):
    return address.is_global or (allow_loopback and address.is_loopback)


def _check_host_policy(host: str, *, allow_loopback: bool, label: str) -> None:
    """Reject a hostname or literal address that is not publicly routable.

    Syntactic only — ``_resolve_and_check`` is the DNS half. Shared so the
    callback and notification paths cannot drift apart.
    """
    loopback_host = host == "localhost" or host.endswith(".localhost")
    if host.endswith((".local", ".internal")) or (loopback_host and not allow_loopback):
        raise OutboundUrlError(f"{label} resolves to a non-public host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return  # a name, not a literal — DNS decides
    if not _address_allowed(address, allow_loopback):
        raise OutboundUrlError(f"{label} resolves to a non-public address")


async def _resolve_and_check(
    host: str, port: int | None, *, allow_loopback: bool, label: str
) -> None:
    """Resolve immediately before connecting and reject any non-global result."""
    try:
        infos = await anyio.to_thread.run_sync(
            lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
    except OSError as e:
        raise OutboundUrlError(f"{label} hostname could not be resolved") from e
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise OutboundUrlError(f"{label} hostname did not resolve")
    if any(
        not _address_allowed(ipaddress.ip_address(address), allow_loopback) for address in addresses
    ):
        raise OutboundUrlError(f"{label} hostname resolves to a non-public address")


def validate_callback_url(
    url: str,
    tenant_settings: dict | None = None,
    *,
    allow_loopback: bool = False,
    allow_private_hosts: bool = False,
    label: str = "callback URL",
) -> tuple[str, int]:
    """Validate syntax and policy without performing network I/O.

    ``allow_loopback`` admits loopback hostnames and addresses — used only by
    the OIDC issuer path so the e2e stub IdP can exercise the real Authlib code
    flow in tests. Production must leave it false. It relaxes loopback only:
    ``.local`` / ``.internal`` stay rejected either way.

    ``allow_private_hosts`` skips the address policy entirely while keeping
    every syntax check (scheme, hostname, no credentials, valid port) — for
    operator-level opt-ins whose destination shares a network with the worker.

    ``label`` names the destination in error messages, which reach API clients.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise OutboundUrlError(f"{label} must use http or https")
    if not parsed.hostname:
        raise OutboundUrlError(f"{label} must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundUrlError(f"{label} must not include credentials")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as e:
        raise OutboundUrlError(f"{label} has an invalid port") from e

    host = parsed.hostname.lower().rstrip(".")
    if not allow_private_hosts:
        _check_host_policy(host, allow_loopback=allow_loopback, label=label)

    allowlist = (tenant_settings or {}).get("callback_allowlist", [])
    if allowlist and not host_allowed(url, allowlist):
        raise OutboundUrlError("callback host is not in the tenant callback allowlist")
    return host, port


async def validate_callback_target(
    url: str,
    tenant_settings: dict | None = None,
    *,
    allow_loopback: bool = False,
    label: str = "callback URL",
) -> None:
    """Resolve the destination immediately before connecting and reject any
    private, loopback, link-local, reserved, or otherwise non-global address.

    Revalidation in the worker closes the queued-job configuration gap. A
    network egress policy remains the strongest defense against DNS rebinding.
    """
    host, port = validate_callback_url(
        url, tenant_settings, allow_loopback=allow_loopback, label=label
    )
    await _resolve_and_check(host, port, allow_loopback=allow_loopback, label=label)


# --- Apprise notification destinations (BUILD_PLAN § Notifications & alerting) ---
#
# Apprise speaks ~250 URL schemes, and two properties make an arbitrary one a
# poor alert target. A few notify the machine rather than the network
# (`dbus://`, `macosx://`, `syslog://`), so a team owner could act on the worker
# host itself. Most of the rest embed a hostname the worker then connects to,
# which turns "add a notification channel" into a probe of everything the worker
# can reach — the same server-side outbound path the callback and link
# validators already close.
#
# So the scheme decides the policy, and a service is listed below only because
# its endpoint is known, not because Apprise supports it. NOTIF_EXTRA_SCHEMES
# widens the set for a deployment that needs one we have not vetted.

# Endpoint fixed by the provider: the URL's authority is credential material
# (`slack://TokenA/TokenB/TokenC`), not a destination, so resolving it would
# reject a perfectly good URL.
HOSTED_APPRISE_SCHEMES = frozenset(
    {
        "discord",
        "gchat",
        "ifttt",
        "join",
        "mailgun",
        "opsgenie",
        "pagerduty",
        "pbul",
        "pover",
        "prowl",
        "sendgrid",
        "ses",
        "slack",
        "sns",
        "tgram",
        "twilio",
    }
)

# Host is a real network destination — self-hosted servers and generic webhooks
# — so it must clear the same address policy as a callback.
#
# `mailto://` is deliberately absent: Apprise does not connect to the URL's host
# but to a provider-mapped server, or `smtp.<domain>` for anything unrecognized,
# so validating the host would not be validating the destination. Email alerts
# go through the hosted senders above (mailgun / sendgrid / ses).
CUSTOM_HOST_APPRISE_SCHEMES = frozenset(
    {
        "apprise",
        "apprises",
        "form",
        "forms",
        "gotify",
        "gotifys",
        "json",
        "jsons",
        "matrix",
        "matrixs",
        "mmost",
        "mmosts",
        "ntfy",
        "ntfys",
        "rocket",
        "rockets",
        "xml",
        "xmls",
    }
)

NOTIF_LABEL = "notification URL"


def notif_policy() -> dict:
    """Operator-level notification policy, as kwargs for the validators below."""
    settings = get_settings()
    return {
        "extra_schemes": frozenset(
            s.strip().lower() for s in settings.notif_extra_schemes.split(",") if s.strip()
        ),
        "allow_private_hosts": settings.notif_allow_private_hosts,
    }


def validate_apprise_url(
    url: str,
    tenant_settings: dict | None = None,
    *,
    extra_schemes: frozenset[str] = frozenset(),
    allow_private_hosts: bool = False,
) -> str | None:
    """Validate an Apprise notification URL without network I/O.

    Returns the hostname that must clear address policy before delivery, or
    ``None`` when the scheme's endpoint is fixed by the provider and the URL's
    authority carries only credentials.

    ``extra_schemes`` (operator-level, NOTIF_EXTRA_SCHEMES) widens the vetted
    set, and anything added there is treated as custom-host — so widening can
    add a destination but never skip the address check on it.
    ``allow_private_hosts`` is for deployments whose alert server shares a
    private network with the worker.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if not scheme:
        raise OutboundUrlError(f"{NOTIF_LABEL} must include a scheme")

    extra = {s.lower() for s in extra_schemes}
    allowed = HOSTED_APPRISE_SCHEMES | CUSTOM_HOST_APPRISE_SCHEMES | extra
    # Tenant policy narrows the platform set; it can never widen it.
    tenant_allowlist = (tenant_settings or {}).get("notif_scheme_allowlist") or []
    if tenant_allowlist:
        allowed &= {str(s).lower() for s in tenant_allowlist}
    if scheme not in allowed:
        raise OutboundUrlError(
            f"notification scheme {scheme!r} is not permitted; allowed: {sorted(allowed)}"
        )
    if scheme in HOSTED_APPRISE_SCHEMES and scheme not in extra:
        return None

    try:
        parsed.port  # noqa: B018 — parses and rejects a malformed port
    except ValueError as e:
        raise OutboundUrlError(f"{NOTIF_LABEL} has an invalid port") from e
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise OutboundUrlError(f"{NOTIF_LABEL} for scheme {scheme!r} must include a hostname")
    if not allow_private_hosts:
        _check_host_policy(host, allow_loopback=False, label=NOTIF_LABEL)
    return host


async def validate_apprise_target(
    url: str,
    tenant_settings: dict | None = None,
    *,
    extra_schemes: frozenset[str] = frozenset(),
    allow_private_hosts: bool = False,
) -> None:
    """Re-check a notification URL immediately before delivery, resolving its
    host so a name that only later points somewhere internal is still refused.
    """
    host = validate_apprise_url(
        url,
        tenant_settings,
        extra_schemes=extra_schemes,
        allow_private_hosts=allow_private_hosts,
    )
    if host is None or allow_private_hosts:
        return
    await _resolve_and_check(host, urlparse(url).port, allow_loopback=False, label=NOTIF_LABEL)


# --- MCP server endpoints (BUILD_PLAN § Stack) ---
#
# A tenant admin registers the endpoint; the worker connects to it on every
# job that grants the server. That makes it a server-initiated outbound
# destination like a callback or a fetched link, and it gets the same
# treatment: scheme and address policy at registration (fast feedback), plus
# a fresh resolution at connect time — a name that was public when the server
# was registered can point at an internal address by the time a job runs.
#
# MCP_ALLOW_PRIVATE_HOSTS widens this for deployments whose MCP servers share
# a network with the worker (the compose `mcp-*` sidecar shape): the full URL
# syntax policy (scheme, hostname, no credentials, valid port) is still
# enforced through the shared validator — only the address policy and the
# connect-time resolution are skipped.

MCP_LABEL = "MCP endpoint"


def validate_mcp_url(url: str) -> None:
    """Registration-time check for an MCP HTTP endpoint. No network I/O."""
    validate_callback_url(
        url,
        allow_private_hosts=get_settings().mcp_allow_private_hosts,
        label=MCP_LABEL,
    )


async def validate_mcp_target(url: str) -> None:
    """Connect-time check: resolve the endpoint and reject any non-public
    address, the same two-phase check callback delivery uses."""
    if get_settings().mcp_allow_private_hosts:
        # No resolution, but a stored endpoint that predates the current
        # syntax policy is still refused rather than connected to.
        validate_callback_url(url, allow_private_hosts=True, label=MCP_LABEL)
        return
    await validate_callback_target(url, label=MCP_LABEL)
