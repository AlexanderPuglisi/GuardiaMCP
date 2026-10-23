from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("filesystem", instructions="Read and write files inside the allowed directories only.")


@mcp.tool(annotations={"readOnlyHint": True})
def read_file(path: Annotated[str, Field(description="Absolute path of the file to read.")]) -> str:
    """Read the complete contents of a file from the file system.

    Only works within allowed directories. Use read_multiple_files when you need several files.
    """
    return path


@mcp.tool(annotations={"destructiveHint": True})
def write_file(path: str, content: str) -> str:
    """Create a new file or completely overwrite an existing file with new content.

    Use with caution: it overwrites existing files without warning.
    """
    return path


@mcp.tool(annotations={"readOnlyHint": True})
def list_directory(path: str) -> list[str]:
    """Get a detailed listing of all files and directories in a specified path."""
    return []


@mcp.tool(annotations={"readOnlyHint": True})
def search_files(path: str, pattern: str) -> list[str]:
    """Recursively search for files and directories matching a pattern.

    The search is case-insensitive and matches partial names.
    """
    return []
