"""Minimal stdio MCP server for grant tests. Usage: mcp_stub.py <marker_dir>

Each tool writes a marker file so tests can assert exactly which tools ran.
"""

import pathlib
import sys

from fastmcp import FastMCP

marker_dir = pathlib.Path(sys.argv[1])
mcp = FastMCP("stub")


@mcp.tool
def allowed_tool() -> str:
    """A tool the test grants access to."""
    (marker_dir / "allowed").write_text("1")
    return "ALLOWED_OK"


@mcp.tool
def forbidden_tool() -> str:
    """A tool outside the grant's tool allowlist."""
    (marker_dir / "forbidden").write_text("1")
    return "FORBIDDEN"


if __name__ == "__main__":
    mcp.run()
