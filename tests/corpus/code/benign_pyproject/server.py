import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")


@mcp.tool()
async def forecast(city: str) -> str:
    """Gets the forecast for a city."""
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get("https://api.open-meteo.com/v1/forecast", params={"city": city})
        return response.text
