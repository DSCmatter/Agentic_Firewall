"""Adapters for MCP targets supported by the existing gateway transports."""

from __future__ import annotations

import asyncio
import contextlib
import json
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx

from benchmarking.attack_harness import get_free_port, start_server, stop_server, wait_for_server


class TargetConfigurationError(ValueError):
    """The supplied CLI target options cannot be safely executed."""


class TargetPreflightError(RuntimeError):
    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass(frozen=True)
class McpTargetConfig:
    kind: Literal["http_sse", "stdio"]
    server_url: str | None = None
    command: tuple[str, ...] = ()

    @classmethod
    def from_options(cls, server_url: str | None, server_cmd: str | None) -> "McpTargetConfig | None":
        if not server_url and not server_cmd:
            return None
        if server_url and server_cmd:
            raise TargetConfigurationError("Use exactly one of --server-url or --server-cmd.")
        if server_url:
            parsed = urlsplit(server_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise TargetConfigurationError("--server-url must be an absolute HTTP(S) MCP server base URL.")
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise TargetConfigurationError("--server-url must not contain credentials, query parameters, or fragments.")
            return cls(kind="http_sse", server_url=urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")))
        try:
            command = json.loads(server_cmd or "")
        except json.JSONDecodeError as exc:
            raise TargetConfigurationError("--server-cmd must be a JSON array of executable arguments.") from exc
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) and arg and "\x00" not in arg for arg in command):
            raise TargetConfigurationError("--server-cmd must be a non-empty JSON array of non-empty strings.")
        return cls(kind="stdio", command=tuple(command))

    def public_description(self) -> dict[str, str]:
        if self.kind == "http_sse":
            return {"kind": "http-sse", "transport": "MCP SSE via gateway", "endpoint": self.server_url or ""}
        return {"kind": "stdio", "transport": "MCP stdio via gateway", "command": "[redacted argv]"}


class McpTargetAdapter:
    """Expose an MCP target through a temporary instance of the existing gateway."""

    def __init__(self, config: McpTargetConfig, timeout_s: float = 10.0) -> None:
        self.config = config
        self.timeout_s = timeout_s
        self.gateway_process = None
        self.gateway_url: str | None = None
        self.available_tools: set[str] = set()

    async def __aenter__(self) -> "McpTargetAdapter":
        port = get_free_port()
        env = {"FW_REAL_SERVER_URL": "", "FW_REAL_SERVER_CMD": ""}
        if self.config.kind == "http_sse":
            env["FW_REAL_SERVER_URL"] = self.config.server_url or ""
        else:
            env["FW_REAL_SERVER_CMD"] = json.dumps(list(self.config.command))
        self.gateway_process = start_server("gateway.mcp_gateway:app", port, env=env)
        try:
            await wait_for_server(self.gateway_process, port, "Scan gateway")
        except RuntimeError as exc:
            self.close()
            raise TargetPreflightError("target_unavailable", "The temporary MCP gateway could not start.") from exc
        self.gateway_url = f"http://127.0.0.1:{port}"
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        # Let gateway SSE disconnect handlers terminate any stdio children first.
        await asyncio.sleep(0.1)
        self.close()

    def close(self) -> None:
        stop_server(self.gateway_process)
        self.gateway_process = None

    async def preflight(self) -> None:
        """Require initialize and tools/list before allowing the attack suite to run."""
        initialize = {
            "jsonrpc": "2.0", "id": 9001, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "agentic-firewall", "version": "0.1.0"},
            },
        }
        async with _GatewaySseSession(self.gateway_url or "", self.timeout_s, identity="__probe__") as session:
            response = await session.request(initialize)
            if not isinstance(response.get("result"), dict):
                self._raise_preflight_error(response, "MCP initialize did not return a valid result.")
            await session.notify({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            tools = await session.request({"jsonrpc": "2.0", "id": 9002, "method": "tools/list", "params": {}})
            if not isinstance(tools.get("result"), dict) or not isinstance(tools["result"].get("tools"), list):
                self._raise_preflight_error(tools, "MCP tools/list did not return a valid tools array.")
            raw_tools = tools["result"]["tools"]
            self.available_tools = {
                t.get("name")
                for t in raw_tools
                if isinstance(t, dict) and isinstance(t.get("name"), str)
            }

    def _raise_preflight_error(self, response: dict[str, Any], fallback: str) -> None:
        text = str(response.get("error", {}).get("message", "")).lower()
        if "auth" in text or "unauthorized" in text or "forbidden" in text:
            raise TargetPreflightError("authentication_failure", "The MCP target rejected authentication.")
        if "connection to backend" in text or "backend server" in text or "starting stdio" in text:
            raise TargetPreflightError("target_unavailable", "The MCP target could not be reached through the gateway.")
        raise TargetPreflightError("mcp_handshake_failure", fallback)


class _GatewaySseSession:
    """Small reusable client for the gateway's existing SSE/message transport."""

    def __init__(self, gateway_url: str, timeout_s: float, identity: str = "__probe__") -> None:
        self.gateway_url = gateway_url
        self.timeout_s = timeout_s
        self.identity = identity
        self.session_id = "scan_preflight"
        self.client: httpx.AsyncClient | None = None
        self.stream_context = None
        self.reader: asyncio.Task | None = None
        self.messages: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.connected = asyncio.Event()
        self.stream_error: Exception | None = None

    async def __aenter__(self) -> "_GatewaySseSession":
        self.client = httpx.AsyncClient(base_url=self.gateway_url, timeout=self.timeout_s)
        self.stream_context = self.client.stream("GET", f"/sse?identity={self.identity}&session_id={self.session_id}")
        response = await self.stream_context.__aenter__()
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            await self.__aexit__(None, None, None)
            status = exc.response.status_code
            kind = "authentication_failure" if status in {401, 403} else "target_unavailable"
            raise TargetPreflightError(kind, "Unable to establish an MCP SSE session.") from exc

        async def read_stream() -> None:
            try:
                self.connected.set()
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line.split("data:", 1)[1].strip()
                    if data.startswith("/message"):
                        continue
                    try:
                        payload = json.loads(data)
                    except json.JSONDecodeError as exc:
                        self.stream_error = exc
                        continue
                    if isinstance(payload, dict):
                        await self.messages.put(payload)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.stream_error = exc
                self.connected.set()

        self.reader = asyncio.create_task(read_stream())
        await asyncio.wait_for(self.connected.wait(), timeout=self.timeout_s)
        # Match the harness's registration delay before posting to /message.
        await asyncio.sleep(0.3)
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        if self.reader:
            self.reader.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.reader
        if self.stream_context:
            await self.stream_context.__aexit__(exc_type, exc, traceback)
        if self.client:
            await self.client.aclose()

    async def notify(self, message: dict[str, Any]) -> None:
        await self._post(message)

    async def request(self, message: dict[str, Any]) -> dict[str, Any]:
        await self._post(message)
        try:
            while True:
                response = await asyncio.wait_for(self.messages.get(), timeout=self.timeout_s)
                # Gateway connection/startup errors are emitted before a request
                # can be correlated, so preserve them for safe classification.
                if response.get("id") == message["id"] or response.get("error", {}).get("code") == -32099:
                    return response
        except asyncio.TimeoutError as exc:
            if self.stream_error:
                raise TargetPreflightError("malformed_mcp_response", "The MCP target returned malformed response data.") from exc
            raise TargetPreflightError("timeout", "Timed out waiting for an MCP preflight response.") from exc

    async def _post(self, message: dict[str, Any]) -> None:
        if self.client is None:
            raise TargetPreflightError("benchmark_execution_error", "The scan gateway is not running.")
        try:
            posted = await self.client.post(f"/message?session_id={self.session_id}&identity={self.identity}", json=message)
            if posted.status_code != 202:
                if posted.status_code in {401, 403}:
                    raise TargetPreflightError("authentication_failure", "The MCP target rejected authentication.")
                if posted.status_code in {502, 503, 504}:
                    raise TargetPreflightError("target_unavailable", "The MCP target is unavailable.")
                raise TargetPreflightError("malformed_mcp_response", "The gateway rejected the MCP request.")
        except httpx.TimeoutException as exc:
            raise TargetPreflightError("timeout", "Timed out sending an MCP preflight request.") from exc
        except httpx.RequestError as exc:
            raise TargetPreflightError("target_unavailable", "The MCP target is unavailable.") from exc
