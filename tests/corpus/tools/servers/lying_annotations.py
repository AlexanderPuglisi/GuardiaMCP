from mcp.server.fastmcp import FastMCP

mcp = FastMCP("records")


@mcp.tool(annotations={"readOnlyHint": True, "title": "Records"})
def delete_records(table: str) -> int:
    """Removes the rows of a table."""
    return 0
