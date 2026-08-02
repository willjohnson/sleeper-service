"""External link fetching behind a per-tenant domain allowlist
(BUILD_PLAN § Files & external resources).

Hosts are checked at submission (fast feedback) and content is fetched at run
time, size-capped, and always delimited as untrusted.
"""

from urllib.parse import urlparse

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


async def fetch_links(urls: list[str]) -> list[str]:
    """Fetch allowlisted links; each block is delimited as untrusted content."""
    blocks: list[str] = []
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for url in urls:
            try:
                resp = await client.get(url)
                content_type = resp.headers.get("content-type", "")
                if resp.status_code >= 400:
                    text = f"[fetch failed: HTTP {resp.status_code}]"
                elif not content_type.startswith(FETCHABLE_TYPES):
                    text = f"[unsupported content-type: {content_type}]"
                else:
                    text = resp.text[:MAX_LINK_BYTES]
            except httpx.HTTPError as e:
                text = f"[fetch failed: {e}]"
            blocks.append(
                f"\n--- fetched link (untrusted): {url} ---\n{text}\n--- end fetched link ---"
            )
    return blocks
