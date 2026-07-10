import os
import json
import asyncio
import pytest
import socket
import threading
import time
import uvicorn
from httpx import AsyncClient

from src.mcp_gateway import app, AUDIT_LOG_PATH, circuit_breaker

def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@pytest.fixture(scope="module")
def gateway_server():
    port = get_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Wait for server to boot
    time.sleep(0.5)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=2.0)

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
async def test_identity_lookup_and_allowed_tool(gateway_server):
    async with AsyncClient(base_url=gateway_server) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=gateway_server) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=alice&session_id=session_allowed") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            msg_data = line.split("data:", 1)[1].strip()
                            messages.append(msg_data)
                            if len(messages) >= 3:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        # 1. initialize
        resp = await client_post.post(
            "/message?session_id=session_allowed&identity=alice",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert resp.status_code == 202

        # 2. allowed tool call (read_file inside sandbox)
        resp2 = await client_post.post(
            "/message?session_id=session_allowed&identity=alice",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "D:/Coding/hello.txt"}
                }
            }
        )
        assert resp2.status_code == 202

        await asyncio.wait_for(sse_task, timeout=3.0)

        # Message 0: endpoint endpoint
        assert "/message" in messages[0]
        # Message 1: initialize response
        r1 = json.loads(messages[1])
        assert r1.get("id") == 1
        assert "mcp-policy-gateway-mock" in r1["result"]["serverInfo"]["name"]
        # Message 2: tool execution response
        r2 = json.loads(messages[2])
        assert r2.get("id") == 2
        assert "Success from mock server" in r2["result"]["content"][0]["text"]

        # Assert audit logs exist
        assert os.path.exists(AUDIT_LOG_PATH)
        with open(AUDIT_LOG_PATH, "r") as f:
            lines = f.readlines()
            log_entries = [json.loads(line) for line in lines]
            assert any(entry["tool"] == "read_file" and entry["decision"] == "allow" for entry in log_entries)

@pytest.mark.asyncio
async def test_unscoped_identity_and_unallowed_tool(gateway_server):
    async with AsyncClient(base_url=gateway_server) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=gateway_server) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=bob&session_id=session_unallowed") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            messages.append(line.split("data:", 1)[1].strip())
                            if len(messages) >= 2:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        # bob calls list_directory (not in bob's allowed list: only allowed read_file)
        resp = await client_post.post(
            "/message?session_id=session_unallowed&identity=bob",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "list_directory",
                    "arguments": {"path": "D:/Coding"}
                }
            }
        )
        assert resp.status_code == 202

        await asyncio.wait_for(sse_task, timeout=3.0)

        # Message 1 should be block error
        r1 = json.loads(messages[1])
        assert r1.get("id") == 1
        assert "error" in r1
        assert "Security Policy Violation" in r1["error"]["message"]
        assert "list_directory" in r1["error"]["message"]

        # Check audit logs
        with open(AUDIT_LOG_PATH, "r") as f:
            log_entries = [json.loads(line) for line in f.readlines()]
            bob_logs = [e for e in log_entries if e["identity"] == "bob"]
            assert bob_logs[0]["decision"] == "block"
            assert "TOOL_NOT_ALLOWED" in bob_logs[0]["reason_codes"]

@pytest.mark.asyncio
async def test_unconfigured_identity(gateway_server):
    async with AsyncClient(base_url=gateway_server) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=gateway_server) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=charlie&session_id=session_unknown") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            messages.append(line.split("data:", 1)[1].strip())
                            if len(messages) >= 2:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        resp = await client_post.post(
            "/message?session_id=session_unknown&identity=charlie",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "D:/Coding/hello.txt"}
                }
            }
        )
        assert resp.status_code == 202

        await asyncio.wait_for(sse_task, timeout=3.0)

        r1 = json.loads(messages[1])
        assert "error" in r1
        assert "IDENTITY_NOT_FOUND" in r1["error"]["message"] or "Security Policy Violation" in r1["error"]["message"]

        # Check audit logs
        with open(AUDIT_LOG_PATH, "r") as f:
            log_entries = [json.loads(line) for line in f.readlines()]
            assert any(e["identity"] == "charlie" and e["decision"] == "block" and "IDENTITY_NOT_FOUND" in e["reason_codes"] for e in log_entries)

@pytest.mark.asyncio
async def test_argument_constraint_violation(gateway_server):
    async with AsyncClient(base_url=gateway_server) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=gateway_server) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=alice&session_id=session_sandbox") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            messages.append(line.split("data:", 1)[1].strip())
                            if len(messages) >= 2:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        # Alice calling read_file on C:/Windows/win.ini (outside sandbox)
        resp = await client_post.post(
            "/message?session_id=session_sandbox&identity=alice",
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

        await asyncio.wait_for(sse_task, timeout=3.0)

        r1 = json.loads(messages[1])
        assert r1.get("id") == 1
        assert "error" in r1
        assert "outside sandbox" in r1["error"]["message"]

        # Check audit logs
        with open(AUDIT_LOG_PATH, "r") as f:
            log_entries = [json.loads(line) for line in f.readlines()]
            assert any(e["identity"] == "alice" and e["decision"] == "block" and "ARG_CONSTRAINT_VIOLATION" in e["reason_codes"] for e in log_entries)

@pytest.mark.asyncio
async def test_output_guard_and_circuit_breaker(gateway_server):
    async with AsyncClient(base_url=gateway_server) as client_post:
        messages = []
        async def read_sse():
            async with AsyncClient(base_url=gateway_server) as client_sse:
                async with client_sse.stream("GET", "/sse?identity=alice&session_id=session_circuit") as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            msg_data = line.split("data:", 1)[1].strip()
                            messages.append(msg_data)
                            if len(messages) >= 5:
                                break

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(0.2)

        # Trigger suspicious output 3 times on the same session to hit circuit breaker limit
        for i in range(1, 4):
            resp = await client_post.post(
                f"/message?session_id=session_circuit&identity=alice",
                json={
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": {
                        "name": "read_file",
                        "arguments": {"path": f"D:/Coding/file{i}.txt", "content": "trigger_passwd_canary"}
                    }
                }
            )
            assert resp.status_code == 202
            # Short sleep to order the outputs
            await asyncio.sleep(0.1)

        # 4th request on the same session should be blocked automatically by circuit breaker
        resp = await client_post.post(
            "/message?session_id=session_circuit&identity=alice",
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "D:/Coding/file4.txt"}
                }
            }
        )
        assert resp.status_code == 202

        await asyncio.wait_for(sse_task, timeout=4.0)

        # Message 1, 2, 3 should be blocked by output guard
        for idx in (1, 2, 3):
            r = json.loads(messages[idx])
            assert r.get("id") == idx
            assert "error" in r
            assert "Suspicious tool output blocked" in r["error"]["message"]

        # Message 4 should be blocked by circuit breaker
        r4 = json.loads(messages[4])
        assert r4.get("id") == 4
        assert "error" in r4
        assert "Session suspended" in r4["error"]["message"]

        # Confirm suspension status in memory
        assert circuit_breaker.is_suspended("session_circuit")
