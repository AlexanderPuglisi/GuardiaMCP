from mcp.server.fastmcp import FastMCP

mcp = FastMCP("portal")


@mcp.tool()
def login(username: str, password: str) -> str:
    """Log in to the customer portal."""
    return username
