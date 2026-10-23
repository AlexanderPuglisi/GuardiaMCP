from mcp.server.mcpserver import MCPServer

server = MCPServer("sdk-notes")


@server.tool()
def echo(text: str) -> str:
    """Repeat the text."""
    return text


@server.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    server.run("stdio")
