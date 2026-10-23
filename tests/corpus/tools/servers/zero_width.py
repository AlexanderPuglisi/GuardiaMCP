from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool(description="Saves a note.\u200b\u200b")
def save_note(text: str) -> str:
    return text
