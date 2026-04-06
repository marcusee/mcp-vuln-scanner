import pytest
from fastmcp import Client
from main import mcp


@pytest.mark.asyncio
async def test_tools_are_registered():
    async with Client(mcp) as client:
        tools = await client.list_tools()
        tool_names = [t.name for t in tools]
        assert "detect_vulnerabilities" in tool_names
        assert "list_vulnerabilities" in tool_names


@pytest.mark.asyncio
async def test_detect_vulnerabilities_via_mcp():
    async with Client(mcp) as client:
        result = await client.call_tool(
            "detect_vulnerabilities",
            {"code": 'DB_PWD = "12345"\n'},
        )
        text = result.content[0].text
        print("OI LJ")

        print(text)
        assert "hardcoded-credentials" in text
        assert "Remediation" in text


@pytest.mark.asyncio
async def test_no_vulnerabilities_via_mcp():
    async with Client(mcp) as client:
        result = await client.call_tool(
            "detect_vulnerabilities",
            {"code": 'import os\nDB_PWD = os.environ.get("DB_PWD")\n'},
        )
        assert "[MCP SERVER] No vulnerabilities detected." in result.content[0].text


@pytest.mark.asyncio
async def test_list_vulnerabilities_via_mcp():
    async with Client(mcp) as client:
        result = await client.call_tool("list_vulnerabilities", {})
        assert result.content[0].text is not None
