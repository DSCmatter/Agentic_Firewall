import asyncio
import sys

import pytest

from agentic_firewall.mcp_target import McpTargetAdapter, McpTargetConfig, TargetConfigurationError, TargetPreflightError
from agentic_firewall.services import run_mcp_target_scan


def test_valid_target_configurations_are_normalized_and_redacted():
    url_config = McpTargetConfig.from_options("http://127.0.0.1:8000/", None)
    command_config = McpTargetConfig.from_options(None, '["python", "server.py"]')

    assert url_config and url_config.server_url == "http://127.0.0.1:8000"
    assert command_config and command_config.command == ("python", "server.py")
    assert command_config.public_description()["command"] == "[redacted argv]"


@pytest.mark.parametrize(
    ("url", "command"),
    [
        ("not-a-url", None),
        ("http://user:secret@localhost:8000", None),
        ("http://localhost:8000?token=secret", None),
        (None, "python server.py"),
        ("http://localhost:8000", '["python"]'),
    ],
)
def test_invalid_target_configuration_is_rejected(url, command):
    with pytest.raises(TargetConfigurationError):
        McpTargetConfig.from_options(url, command)


@pytest.mark.asyncio
async def test_unreachable_target_is_reported_as_infrastructure_error():
    config = McpTargetConfig.from_options("http://127.0.0.1:1", None)
    assert config is not None

    report = await run_mcp_target_scan(config)

    assert len(report.results) == 17
    assert {result.status for result in report.results} == {"ERROR"}
    assert report.results[0].evidence["infrastructure_error"]["kind"] == "target_unavailable"


@pytest.mark.parametrize(
    "error_kind",
    ["mcp_handshake_failure", "timeout", "malformed_mcp_response", "authentication_failure"],
)
@pytest.mark.asyncio
async def test_preflight_error_categories_become_infrastructure_reports(monkeypatch, error_kind):
    config = McpTargetConfig.from_options("http://127.0.0.1:1", None)
    assert config is not None

    async def preflight_failure(self):
        raise TargetPreflightError(error_kind, f"failure: {error_kind}")

    monkeypatch.setattr(McpTargetAdapter, "preflight", preflight_failure)
    report = await run_mcp_target_scan(config)
    assert report.results[0].evidence["infrastructure_error"]["kind"] == error_kind
    assert report.results[0].status == "ERROR"


@pytest.mark.asyncio
async def test_preflight_timeout_error(monkeypatch):
    config = McpTargetConfig(kind="http_sse", server_url="http://127.0.0.1:8000")
    adapter = McpTargetAdapter(config, timeout_s=0.05)
    adapter.gateway_url = "http://127.0.0.1:8000"

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def request(self, msg):
            raise TargetPreflightError("timeout", "Timed out waiting for an MCP preflight response.")

        async def notify(self, msg):
            pass

    monkeypatch.setattr("agentic_firewall.mcp_target._GatewaySseSession", lambda url, timeout: FakeSession())
    with pytest.raises(TargetPreflightError) as exc_info:
        await adapter.preflight()
    assert exc_info.value.kind == "timeout"


@pytest.mark.asyncio
async def test_preflight_malformed_response_error(monkeypatch):
    config = McpTargetConfig(kind="http_sse", server_url="http://127.0.0.1:8000")
    adapter = McpTargetAdapter(config)
    adapter.gateway_url = "http://127.0.0.1:8000"

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def request(self, msg):
            # initialize returns something without dict result
            return {"jsonrpc": "2.0", "id": msg["id"], "result": "invalid"}

        async def notify(self, msg):
            pass

    monkeypatch.setattr("agentic_firewall.mcp_target._GatewaySseSession", lambda url, timeout: FakeSession())
    with pytest.raises(TargetPreflightError) as exc_info:
        await adapter.preflight()
    assert exc_info.value.kind == "mcp_handshake_failure"


@pytest.mark.asyncio
async def test_stdio_gateway_process_is_stopped_after_preflight():
    server_code = """
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    method = message.get('method')
    if method == 'initialize':
        result = {'serverInfo': {'name': 'test', 'version': '1'}, 'capabilities': {}}
    elif method == 'tools/list':
        result = {'tools': []}
    else:
        continue
    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': result}), flush=True)
"""
    config = McpTargetConfig(kind="stdio", command=(sys.executable, "-c", server_code))
    adapter = McpTargetAdapter(config)
    async with adapter as active:
        process = active.gateway_process
        await active.preflight()
    await asyncio.sleep(0.2)

    assert process is not None
    assert process.poll() is not None
