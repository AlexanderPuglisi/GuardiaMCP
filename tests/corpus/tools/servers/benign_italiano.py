from mcp.server.fastmcp import FastMCP

mcp = FastMCP("progetto")


@mcp.tool()
def cerca_file(cartella: str, testo: str) -> list[str]:
    """Cerca file nel progetto. Chiedi conferma all'utente prima di cancellare qualcosa."""
    return []


@mcp.tool()
def riassumi(testo: str) -> str:
    """Riassume il testo indicato dall'utente in tre frasi."""
    return testo
