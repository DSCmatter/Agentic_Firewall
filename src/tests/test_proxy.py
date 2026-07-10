import os
import json
import asyncio
import pytest
import socket
import threading
import time
import uvicorn
from httpx import AsyncClient

# Import app from gateway
from src.gateway.mcp_gateway import app as gateway_app, AUDIT_LOG_PATH, circuit_breaker
# Import app from toy_server
from src.toy_server.toy_server import app as toy_app

def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="module")
def servers():
    # Spin up toy server first
    toy_port = get_free_port()
    toy_config = uvicorn.Config(toy_app, host="127.0.0.1", port=toy_port, log_level="warning")
    toy_server = uvicorn.Server(toy_config)
    toy_thread = threading.Thread(target=toy_server.run, daemon=True)
    toy_thread.start()

    # Configure gateway environment pointing to the real server
    real_url = f"http://127.0.0.1:{toy_port}"
    os.environ["FW_REAL_SERVER_URL"] = real_url
    import src.gateway.mcp_gateway as gw
    gw.REAL_SERVER_URL = real_url

    # Spin up gateway
    gw_port = get_free_port()
    gw_config = uvicorn.Config(gateway_app, host="127.0.0.1", port=gw_port, log_level="warning")
    gw_server = uvicorn.Server(gw_config)
    gw_thread = threading.Thread(target=gw_server.run, daemon=True)
    gw_thread.start()

    # Wait for servers to boot
    time.sleep(0.8)

    yield f"http://127.0.0.1:{gw_port}"

    # Tear down
    toy_server.should_exit = True
    gw_server.should_exit = True
    toy_thread.join(timeout=2.0)
    gw_thread.join(timeout=2.0)

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
async def test_proxy_tools_list_filtering(servers):
    async with AsyncClient(base_url=servers) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=servers) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=bob&session_id=session_tools") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            msg_data = line.split("data:", 1)[1].strip()
                            messages.append(msg_data)
                            if len(messages) >= 2:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        resp = await client_post.post(
            "/message?session_id=session_tools&identity=bob",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        assert resp.status_code == 202

        await asyncio.wait_for(sse_task, timeout=4.0)

        # Parse messages
        parsed_msgs = {json.loads(m).get("id"): json.loads(m) for m in messages if not m.startswith("/message")}
        r1 = parsed_msgs.get(1)
        assert r1 is not None
        tools = r1["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        # Bob is only allowed 'read_file' in policy_v2.json
        assert "read_file" in tool_names
        assert "execute_command" not in tool_names
        assert len(tool_names) == 1

@pytest.mark.asyncio
async def test_proxy_allowed_and_blocked_requests(servers):
    async with AsyncClient(base_url=servers) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=servers) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=alice&session_id=session_requests") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            msg_data = line.split("data:", 1)[1].strip()
                            messages.append(msg_data)
                            if len(messages) >= 3:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        # 1. Initialize
        resp = await client_post.post(
            "/message?session_id=session_requests&identity=alice",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert resp.status_code == 202

        # 2. Blocked tool request (alice is not allowed 'execute_command')
        resp2 = await client_post.post(
            "/message?session_id=session_requests&identity=alice",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "execute_command",
                    "arguments": {"command": "whoami"}
                }
            }
        )
        assert resp2.status_code == 202

        await asyncio.wait_for(sse_task, timeout=4.0)

        # Parse messages and assert properties
        parsed_msgs = {json.loads(m).get("id"): json.loads(m) for m in messages if not m.startswith("/message")}
        
        # Verify initialize response (id=1)
        r1 = parsed_msgs.get(1)
        assert r1 is not None
        assert "toy-mcp-server" in r1["result"]["serverInfo"]["name"]

        # Verify block response (id=2)
        r2 = parsed_msgs.get(2)
        assert r2 is not None
        assert "error" in r2
        assert "Security Policy Violation" in r2["error"]["message"]

@pytest.mark.asyncio
async def test_proxy_sandbox_constraint(servers):
    async with AsyncClient(base_url=servers) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=servers) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=alice&session_id=session_sandbox_proxy") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            msg_data = line.split("data:", 1)[1].strip()
                            messages.append(msg_data)
                            if len(messages) >= 2:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        # Alice calling read_file outside sandbox
        resp = await client_post.post(
            "/message?session_id=session_sandbox_proxy&identity=alice",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "C:/Windows/win.ini"}
                }
            }
        )
        assert resp.status_code == 202

        await asyncio.wait_for(sse_task, timeout=4.0)

        # Message 1 should be block error
        r1 = json.loads(messages[1])
        assert r1.get("id") == 1
        assert "outside sandbox" in r1["error"]["message"]

@pytest.mark.asyncio
async def test_proxy_output_guard_and_circuit_breaker(servers):
    async with AsyncClient(base_url=servers) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=servers) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=alice&session_id=session_cb_proxy") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            msg_data = line.split("data:", 1)[1].strip()
                            messages.append(msg_data)
                            if len(messages) >= 5:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        # Trigger suspicious tool response 3 times (read_file inside sandbox is allowed for alice)
        for i in range(1, 4):
            resp = await client_post.post(
                "/message?session_id=session_cb_proxy&identity=alice",
                json={
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {"path": f"D:/Coding/temp{i}.txt", "content": "trigger_passwd_canary"}
                    }
                }
            )
            assert resp.status_code == 202
            await asyncio.sleep(0.15)

        # 4th request on the same session should be automatically blocked by circuit breaker
        resp = await client_post.post(
            "/message?session_id=session_cb_proxy&identity=alice",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "D:/Coding/hello.txt"}
                }
            }
        )
        assert resp.status_code == 202

        await asyncio.wait_for(sse_task, timeout=5.0)

        # Parse messages
        parsed_msgs = {json.loads(m).get("id"): json.loads(m) for m in messages if not m.startswith("/message")}

        # Message 1, 2, 3 should be blocked by Output Guard (suspicious output flagged)
        for idx in (1, 2, 3):
            r = parsed_msgs.get(idx)
            assert r is not None
            assert "error" in r
            assert "Suspicious tool output blocked" in r["error"]["message"]

        # Message 4 should be blocked by Circuit Breaker (session suspended)
        r4 = parsed_msgs.get(4)
        assert r4 is not None
        assert "error" in r4
        assert "Session suspended" in r4["error"]["message"]

        # Confirm suspension
        assert circuit_breaker.is_suspended("session_cb_proxy")
