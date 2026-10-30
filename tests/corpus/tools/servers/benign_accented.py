from mcp.server.fastmcp import FastMCP

mcp = FastMCP("library")


@mcp.tool(name="résumé_search", description="Searches résumés by keyword.")
def search() -> str:
    return ""
