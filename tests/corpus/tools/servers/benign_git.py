from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def git_status(repo_path: str) -> str:
    """Shows the working tree status."""
    return ""


@mcp.tool()
def git_diff(repo_path: str, target: str = "HEAD") -> str:
    """Shows differences between branches or commits. Before committing, review the diff with the user."""
    return ""


@mcp.tool()
def git_commit(repo_path: str, message: str) -> str:
    """Records changes to the repository with the given message."""
    return ""
