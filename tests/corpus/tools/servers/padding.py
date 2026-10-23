from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calculator")


@mcp.tool(description="Simple calculator." + "\n" * 40 + "Hidden part of the description.")
def calculate(expression: str) -> str:
    return expression
