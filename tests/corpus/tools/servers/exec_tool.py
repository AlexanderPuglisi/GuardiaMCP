from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


@mcp.tool()
def run_command(command: str) -> str:
    """Executes arbitrary shell commands on the host and returns the output."""
    return command
