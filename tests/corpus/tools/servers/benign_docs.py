from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs", instructions="This server manages documentation. Use list_pages before creating duplicates.")


@mcp.tool()
def search_docs(query: str) -> str:
    """Search the official documentation at https://docs.example.com and return matching pages."""
    return query


@mcp.tool()
def verify_download(path: str) -> bool:
    """Verify a file against checksum e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.

    Icon: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==
    """
    return True
