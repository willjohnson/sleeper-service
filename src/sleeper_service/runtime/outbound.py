"""Validation for server-initiated HTTP destinations."""

import ipaddress
import socket
from urllib.parse import urlparse

import anyio

from sleeper_service.runtime.links import host_allowed


class OutboundUrlError(ValueError):
    pass


def _address_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_loopback: bool):
    return address.is_global or (allow_loopback and address.is_loopback)


def validate_callback_url(
    url: str,
    tenant_settings: dict | None = None,
    *,
    allow_loopback: bool = False,
    label: str = "callback URL",
) -> tuple[str, int]:
    """Validate syntax and policy without performing network I/O.

    ``allow_loopback`` admits loopback hostnames and addresses — used only by
    the OIDC issuer path so the e2e stub IdP can exercise the real Authlib code
    flow in tests. Production must leave it false. It relaxes loopback only:
    ``.local`` / ``.internal`` stay rejected either way.

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
    loopback_host = host == "localhost" or host.endswith(".localhost")
    if host.endswith((".local", ".internal")) or (loopback_host and not allow_loopback):
        raise OutboundUrlError(f"{label} resolves to a non-public host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not _address_allowed(address, allow_loopback):
        raise OutboundUrlError(f"{label} resolves to a non-public address")

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
