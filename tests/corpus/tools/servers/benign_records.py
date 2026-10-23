from mcp.server.fastmcp import FastMCP

mcp = FastMCP("records")


@mcp.tool(annotations={"readOnlyHint": True})
def list_records(table: str) -> list[dict[str, str]]:
    """List the rows of a table."""
    return []


@mcp.tool(annotations={"destructiveHint": True})
def delete_record(table: str, record_id: str) -> bool:
    """Delete a single row. Ask the user to confirm first."""
    return True


@mcp.prompt()
def review_table(table: str) -> str:
    """Review the content of a table and suggest improvements."""
    return f"Review the table {table}."


@mcp.resource("records://{table}/schema")
def table_schema(table: str) -> str:
    """Schema of a table."""
    return table
