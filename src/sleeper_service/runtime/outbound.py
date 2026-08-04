"""Validation for server-initiated HTTP destinations."""

import ipaddress
import socket
from urllib.parse import urlparse

import anyio

from sleeper_service.runtime.links import host_allowed


class OutboundUrlError(ValueError):
    pass


def validate_callback_url(url: str, tenant_settings: dict | None = None) -> tuple[str, int]:
    """Validate syntax and policy without performing network I/O."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise OutboundUrlError("callback URL must use http or https")
    if not parsed.hostname:
        raise OutboundUrlError("callback URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundUrlError("callback URL must not include credentials")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as e:
        raise OutboundUrlError("callback URL has an invalid port") from e

    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise OutboundUrlError("callback URL resolves to a non-public host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise OutboundUrlError("callback URL resolves to a non-public address")

    allowlist = (tenant_settings or {}).get("callback_allowlist", [])
    if allowlist and not host_allowed(url, allowlist):
        raise OutboundUrlError("callback host is not in the tenant callback allowlist")
    return host, port


async def validate_callback_target(url: str, tenant_settings: dict | None = None) -> None:
    """Resolve the destination immediately before connecting and reject any
    private, loopback, link-local, reserved, or otherwise non-global address.

    Revalidation in the worker closes the queued-job configuration gap. A
    network egress policy remains the strongest defense against DNS rebinding.
    """
    host, port = validate_callback_url(url, tenant_settings)
    try:
        infos = await anyio.to_thread.run_sync(
            lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
    except OSError as e:
        raise OutboundUrlError("callback hostname could not be resolved") from e
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise OutboundUrlError("callback hostname did not resolve")
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise OutboundUrlError("callback hostname resolves to a non-public address")
