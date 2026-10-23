from mcp.server.fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("weather")


@mcp.tool()
async def get_forecast(
    latitude: float = Field(description="Latitude of the location"),
    longitude: float = Field(description="Longitude of the location"),
) -> str:
    """Get the weather forecast for a location.

    Requires an API key set in the WEATHER_API_KEY environment variable.
    """
    return ""


@mcp.tool()
async def get_alerts(state: str = "CA") -> str:
    """Get weather alerts for a US state. Use the two-letter state code."""
    return state
