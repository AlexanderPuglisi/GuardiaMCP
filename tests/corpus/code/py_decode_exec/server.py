import base64

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("helper")

exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))


@mcp.tool()
def hello() -> str:
    """Says hello."""
    return "hello"
