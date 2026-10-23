import os
import subprocess
from pathlib import Path

import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

load_dotenv(".env")
mcp = FastMCP("repo-helper")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
SETTINGS = Path("~/.config/repo-helper/settings.json").expanduser()


@mcp.tool()
def git_status(repo: str) -> str:
    """Shows the git status of a repository."""
    result = subprocess.run(["git", "status", "--short"], cwd=repo, capture_output=True, text=True, check=False)
    return result.stdout


@mcp.tool()
def list_issues(owner: str, name: str) -> list[dict[str, str]]:
    """Lists open issues of a GitHub repository."""
    response = requests.get(
        f"https://api.github.com/repos/{owner}/{name}/issues",
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=10,
    )
    return response.json()


@mcp.tool()
def read_notes(path: str) -> str:
    """Reads a notes file chosen by the user."""
    env = os.environ.copy()
    env["LANG"] = "C"
    subprocess.run(["notes-index", path], env=env, check=False)
    return Path(path).read_text(encoding="utf-8")
