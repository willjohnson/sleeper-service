"""External link fetching behind a per-tenant domain allowlist
(BUILD_PLAN § Files & external resources).

Hosts are checked at submission (fast feedback) and content is fetched at run
time, size-capped, and always delimited as untrusted.
"""

from urllib.parse import urljoin, urlparse

import httpx

MAX_LINK_BYTES = 100_000
FETCHABLE_TYPES = ("text/", "application/json", "application/xml")


def host_allowed(url: str, allowlist: list[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    return any(host == entry.lower() or host.endswith("." + entry.lower()) for entry in allowlist)


def check_links(urls: list[str], tenant_settings: dict) -> str | None:
    """Return an error message if any link is not allowlisted."""
    allowlist = tenant_settings.get("link_allowlist", [])
    for url in urls:
        if urlparse(url).scheme not in ("http", "https"):
            return f"link {url!r} must be http(s)"
        if not host_allowed(url, allowlist):
            return f"link host not in tenant allowlist: {url}"
    return None


async def _fetch_one_link(client: httpx.AsyncClient, url: str, allowlist: list[str]) -> str:
    # Imported here, not at module scope: outbound imports host_allowed from
    # this module.
    from sleeper_service.runtime.outbound import OutboundUrlError, validate_callback_target

    current_url = url
    max_redirects = 5
    for _ in range(max_redirects):
        parsed = urlparse(current_url)
        if parsed.scheme not in ("http", "https"):
            return f"[fetch failed: disallowed scheme {parsed.scheme!r}]"
        if not host_allowed(current_url, allowlist):
            return f"[fetch failed: host not in tenant allowlist: {current_url}]"
        # The allowlist says which hosts a tenant *wants* fetched; it does not
        # say where those hosts resolve. Without this, an allowlist entry (which
        # a tenant admin controls) could be an internal address or a name with a
        # private A record, and the worker — which sits on the internal network
        # and holds SECRET_KEY — would fetch it and hand the body to the model.
        # Same two-phase check the callback and OIDC paths use, re-run per hop.
        try:
            await validate_callback_target(current_url, label="link")
        except OutboundUrlError as e:
            return f"[fetch failed: {e}]"

        try:
            resp = await client.get(current_url, follow_redirects=False)
        except httpx.HTTPError as e:
            return f"[fetch failed: {e}]"

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location")
            if not location:
                return f"[fetch failed: HTTP {resp.status_code} missing Location header]"
            current_url = urljoin(current_url, location)
            continue

        content_type = resp.headers.get("content-type", "")
        if resp.status_code >= 400:
            return f"[fetch failed: HTTP {resp.status_code}]"
        if not content_type.startswith(FETCHABLE_TYPES):
            return f"[unsupported content-type: {content_type}]"
        return resp.text[:MAX_LINK_BYTES]

    return "[fetch failed: too many redirects]"


async def fetch_links(urls: list[str], tenant_settings: dict | None = None) -> list[str]:
    """Fetch allowlisted links; each block is delimited as untrusted content."""
    blocks: list[str] = []
    # Same deny-by-default as check_links: no allowlist configured, no fetches.
    allowlist = (tenant_settings or {}).get("link_allowlist", [])
    async with httpx.AsyncClient(timeout=10) as client:
        for url in urls:
            text = await _fetch_one_link(client, url, allowlist)
            blocks.append(
                f"\n--- fetched link (untrusted): {url} ---\n{text}\n--- end fetched link ---"
            )
    return blocks
