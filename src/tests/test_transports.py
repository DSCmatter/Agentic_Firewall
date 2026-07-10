import os
import json
import asyncio
import pytest
import socket
import threading
import time
import sys
import uvicorn
import websockets
from httpx import AsyncClient

from src.gateway.mcp_gateway import app as gateway_app, AUDIT_LOG_PATH, circuit_breaker

def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(autouse=True)
def reset_circuit_breaker():
    circuit_breaker.flags.clear()
    circuit_breaker.suspended_sessions.clear()
    if os.path.exists(AUDIT_LOG_PATH):
        try:
            os.remove(AUDIT_LOG_PATH)
        except Exception:
            pass

@pytest.mark.asyncio
async def test_stdio_backend_and_websocket_client():
    # 1. Prepare dummy stdio server script
    # It must handle json-rpc messages on stdin and write to stdout.
    dummy_code = """
import sys
import json

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    method = msg.get("method")
    msg_id = msg.get("id")
    if method == "tools/list":
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {"name": "read_file", "description": "Read file"},
                    {"name": "execute_command", "description": "Run command"}
                ]
            }
        }
    elif method == "tools/call":
        tool_name = msg["params"]["name"]
        args = msg["params"].get("arguments", {})
        path_arg = args.get("path", "")
        if "trigger_passwd_canary" in path_arg:
            text = "root:x:0:0:root:/root:/bin/bash"
        else:
            text = f"Executed {tool_name} with path {path_arg}"
        
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [{"type": "text", "text": text}]
            }
        }
    else:
        resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    sys.stdout.write(json.dumps(resp) + "\\n")
    sys.stdout.flush()
"""

    # Configure environmental variable for gateway stdio spawning
    cmd_list = [sys.executable, "-c", dummy_code]
    os.environ["FW_REAL_SERVER_CMD"] = json.dumps(cmd_list)
    # Clear remote server url to force stdio subprocess mode
    if "FW_REAL_SERVER_URL" in os.environ:
        del os.environ["FW_REAL_SERVER_URL"]

    # Spin up gateway
    gw_port = get_free_port()
    gw_config = uvicorn.Config(gateway_app, host="127.0.0.1", port=gw_port, log_level="warning")
    gw_server = uvicorn.Server(gw_config)
    gw_thread = threading.Thread(target=gw_server.run, daemon=True)
    gw_thread.start()

    # Wait for gateway to boot
    await asyncio.sleep(0.8)

    ws_url = f"ws://127.0.0.1:{gw_port}/ws?identity=alice&session_id=session_transport_test"

    try:
        async with websockets.connect(ws_url) as ws:
            # First message should be the endpoint event
            endpoint_msg = await ws.recv()
            assert "event: endpoint" in endpoint_msg

            # Let's request tools/list
            # Alice is allowed read_file, but NOT execute_command in policy_v2.json
            list_req = {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}}
            await ws.send(json.dumps(list_req))

            # Receive the response
            list_resp_str = await ws.recv()
            assert "event: message" in list_resp_str
            # Parse the message part out of the SSE format
            data_part = list_resp_str.split("data: ", 1)[1].split("\n\n", 1)[0].strip()
            list_resp = json.loads(data_part)
            assert list_resp.get("id") == 10
            tools = list_resp["result"]["tools"]
            tool_names = [t["name"] for t in tools]
            assert "read_file" in tool_names
            assert "execute_command" not in tool_names # execute_command was filtered out!

            # Let's request tools/call for read_file inside sandbox (Allowed)
            call_req_allowed = {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "D:/Coding/hello.txt"}
                }
            }
            await ws.send(json.dumps(call_req_allowed))

            call_resp_str = await ws.recv()
            assert "event: message" in call_resp_str
            data_part = call_resp_str.split("data: ", 1)[1].split("\n\n", 1)[0].strip()
            call_resp = json.loads(data_part)
            assert call_resp.get("id") == 11
            assert "result" in call_resp
            assert "Executed read_file" in call_resp["result"]["content"][0]["text"]

            # Let's request tools/call for execute_command (Blocked by Policy Engine)
            call_req_blocked = {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "execute_command",
                    "arguments": {"command": "whoami"}
                }
            }
            await ws.send(json.dumps(call_req_blocked))

            call_resp_str2 = await ws.recv()
            assert "event: message" in call_resp_str2
            data_part = call_resp_str2.split("data: ", 1)[1].split("\n\n", 1)[0].strip()
            call_resp2 = json.loads(data_part)
            assert call_resp2.get("id") == 12
            assert "error" in call_resp2
            assert "Security Policy Violation" in call_resp2["error"]["message"]

            # Let's request path traversal read (Blocked by Sandbox constraints)
            call_req_traversal = {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "C:/Windows/win.ini"}
                }
            }
            await ws.send(json.dumps(call_req_traversal))

            call_resp_str3 = await ws.recv()
            assert "event: message" in call_resp_str3
            data_part = call_resp_str3.split("data: ", 1)[1].split("\n\n", 1)[0].strip()
            call_resp3 = json.loads(data_part)
            assert call_resp3.get("id") == 13
            assert "outside sandbox" in call_resp3["error"]["message"]

    finally:
        gw_server.should_exit = True
        gw_thread.join(timeout=2.0)
        if "FW_REAL_SERVER_CMD" in os.environ:
            del os.environ["FW_REAL_SERVER_CMD"]
