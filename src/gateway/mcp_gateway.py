import os
import json
import uuid
import asyncio
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
import httpx

# Import from security modules
from security.policy_engine import Decision

# Import from local modules
from gateway.state import (
    session_manager,
    circuit_breaker,
    log_audit_event,
    AUDIT_LOG_PATH,
    LOG_PATH,
    POLICY_PATH
)
from gateway.transports import (
    get_real_server_url,
    get_real_server_cmd,
    log_proc_stderr,
    listen_to_stdio_backend,
    listen_to_backend_stream,
    load_policy,
    policy_engine
)
from gateway.mock_server import mock_execute_tool

# Global HTTP Client Pool
http_client: Optional[httpx.AsyncClient] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient()
    yield
    await http_client.aclose()

# FastAPI App
app = FastAPI(title="MCP Policy Gateway", version="2.0.0", lifespan=lifespan)

@app.get("/sse")
async def sse_endpoint(
    request: Request,
    identity: str = Query("anonymous"),
    session_id: Optional[str] = Query(None)
):
    if not session_id:
        session_id = str(uuid.uuid4())

    async def event_generator():
        queue = session_manager.create_session(session_id, identity)
        
        # Send initial message endpoint to client
        yield f"event: endpoint\ndata: /message?session_id={session_id}&identity={identity}\n\n"
        cmd = get_real_server_cmd()
        backend_task = None
        stderr_task = None

        if cmd:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                session_manager.processes[session_id] = proc
                backend_task = asyncio.create_task(
                    listen_to_stdio_backend(session_id, identity, proc)
                )
                stderr_task = asyncio.create_task(
                    log_proc_stderr(proc)
                )
            except Exception as e:
                print(f"Error starting stdio backend command: {e}")
                err = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32099,
                        "message": f"Starting stdio backend process failed: {e}"
                    }
                }
                yield f"event: message\ndata: {json.dumps(err)}\n\n"
        elif get_real_server_url() and http_client:
            try:
                req = http_client.build_request("GET", f"{get_real_server_url()}/sse?session_id={session_id}")
                response = await http_client.send(req, stream=True)
                backend_task = asyncio.create_task(
                    listen_to_backend_stream(session_id, identity, response)
                )
            except Exception as e:
                print(f"Error connecting to backend MCP: {e}")
                err = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32099,
                        "message": f"Connection to backend server failed: {e}"
                    }
                }
                yield f"event: message\ndata: {json.dumps(err)}\n\n"

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield f"event: message\ndata: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            if backend_task:
                backend_task.cancel()
            if stderr_task:
                stderr_task.cancel()
            session_manager.remove_session(session_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/message")
async def post_message(
    request: Request,
    session_id: str = Query(...),
    identity: str = Query("anonymous")
):
    try:
        body = await request.body()
        message = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    msg_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})

    # Verify session exists
    q = session_manager.get_queue(session_id)
    if not q:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    # Verify identity matches the pinned session identity
    registered_identity = session_manager.get_identity(session_id)
    if registered_identity != identity:
        err_resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32602,
                "message": f"Security Policy Violation: Identity mismatch for session {session_id} (registered={registered_identity}, request={identity})"
            }
        }
        log_audit_event(
            identity=identity,
            session_id=session_id,
            tool=params.get("name") if method == "tools/call" else None,
            args=params.get("arguments") if method == "tools/call" else None,
            decision="block",
            reason=f"Session identity pollution mismatch (registered={registered_identity}, request={identity})",
            reason_codes=["IDENTITY_MISMATCH"],
            risk_score=1.0
        )
        await q.put(json.dumps(err_resp))
        return Response(status_code=202)

    # 1. Circuit Breaker Check
    if circuit_breaker.is_suspended(session_id):
        err_resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32000,
                "message": "Security Policy Violation: Session suspended due to repeated security flags."
            }
        }
        log_audit_event(
            identity=identity,
            session_id=session_id,
            tool=params.get("name") if method == "tools/call" else None,
            args=params.get("arguments") if method == "tools/call" else None,
            decision="block",
            reason="Session suspended by circuit breaker.",
            reason_codes=["SESSION_SUSPENDED"],
            risk_score=1.0
        )
        q = session_manager.get_queue(session_id)
        if q:
            await q.put(json.dumps(err_resp))
        return Response(status_code=202)

    # 2. Intercept tools/call for policy checking
    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        policy_engine.policy = load_policy()
        result = policy_engine.evaluate(identity, tool_name, tool_args)

        log_audit_event(
            identity=identity,
            session_id=session_id,
            tool=tool_name,
            args=tool_args,
            decision=result.decision.value,
            reason=result.reason,
            reason_codes=result.reason_codes,
            risk_score=result.risk_score
        )

        if result.decision == Decision.BLOCK:
            err_resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": f"Security Policy Violation: {result.reason}"
                }
            }
            q = session_manager.get_queue(session_id)
            if q:
                await q.put(json.dumps(err_resp))
            return Response(status_code=202)

    # 3. Forward to backend if subprocess or REAL_SERVER_URL is configured
    proc = session_manager.processes.get(session_id)
    if proc:
        async def forward_to_stdio():
            try:
                proc.stdin.write(json.dumps(message).encode() + b"\n")
                await proc.stdin.drain()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32099,
                        "message": f"Error writing to stdio backend process: {e}"
                    }
                }
                q = session_manager.get_queue(session_id)
                if q:
                    await q.put(json.dumps(err_resp))
        asyncio.create_task(forward_to_stdio())
        return Response(status_code=202)

    elif get_real_server_url():
        # Wait up to 2 seconds for backend session to establish
        for _ in range(20):
            backend_url = session_manager.backend_urls.get(session_id)
            if backend_url:
                break
            await asyncio.sleep(0.1)
        else:
            raise HTTPException(status_code=503, detail="Backend session initialization not ready")

        async def forward_to_backend():
            try:
                if http_client:
                    resp = await http_client.post(backend_url, json=message, timeout=10.0)
                    if resp.status_code != 202:
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32099,
                                "message": f"Backend server returned status code {resp.status_code}"
                            }
                        }
                        q = session_manager.get_queue(session_id)
                        if q:
                            await q.put(json.dumps(err_resp))
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32099,
                        "message": f"Error proxying request to backend: {e}"
                    }
                }
                q = session_manager.get_queue(session_id)
                if q:
                    await q.put(json.dumps(err_resp))

        asyncio.create_task(forward_to_backend())
        return Response(status_code=202)

    # 4. Fallback Mock Server execution (when not proxying)
    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        asyncio.create_task(mock_execute_tool(session_id, identity, msg_id, tool_name, tool_args))

    elif method == "initialize":
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {
                    "name": "mcp-policy-gateway-mock",
                    "version": "1.0.0"
                }
            }
        }
        q = session_manager.get_queue(session_id)
        if q:
            await q.put(json.dumps(resp))

    elif method == "tools/list":
        policy_engine.policy = load_policy()
        all_tools = [
            {"name": "read_file", "description": "Read file content"},
            {"name": "write_file", "description": "Write file content"},
            {"name": "list_directory", "description": "List directory content"},
            {"name": "execute_command", "description": "Run shell command"}
        ]
        tool_policy = policy_engine.policy.identities.get(identity)
        allowed_names = set(tool_policy.allowed_tools) if tool_policy else set()
        filtered = [t for t in all_tools if t["name"] in allowed_names]

        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": filtered
            }
        }
        q = session_manager.get_queue(session_id)
        if q:
            await q.put(json.dumps(resp))
    else:
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {}
        }
        q = session_manager.get_queue(session_id)
        if q:
            await q.put(json.dumps(resp))

    return Response(status_code=202)

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    identity: str = Query("anonymous"),
    session_id: Optional[str] = Query(None)
):
    if not session_id:
        session_id = str(uuid.uuid4())

    await websocket.accept()

    queue = session_manager.create_session(session_id, identity)
    
    # Send initial message endpoint info
    await websocket.send_text(f"event: endpoint\ndata: /message?session_id={session_id}&identity={identity}\n\n")

    cmd = get_real_server_cmd()
    backend_task = None
    stderr_task = None

    if cmd:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            session_manager.processes[session_id] = proc
            backend_task = asyncio.create_task(
                listen_to_stdio_backend(session_id, identity, proc)
            )
            stderr_task = asyncio.create_task(
                log_proc_stderr(proc)
            )
        except Exception as e:
            print(f"Error starting stdio backend command: {e}")
            err = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32099,
                    "message": f"Starting stdio backend process failed: {e}"
                }
            }
            await websocket.send_text(f"event: message\ndata: {json.dumps(err)}\n\n")
    elif get_real_server_url() and http_client:
        try:
            req = http_client.build_request("GET", f"{get_real_server_url()}/sse?session_id={session_id}")
            response = await http_client.send(req, stream=True)
            backend_task = asyncio.create_task(
                listen_to_backend_stream(session_id, identity, response)
            )
        except Exception as e:
            print(f"Error connecting to backend MCP: {e}")
            err = {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32099,
                    "message": f"Connection to backend server failed: {e}"
                }
            }
            await websocket.send_text(f"event: message\ndata: {json.dumps(err)}\n\n")

    # Task to pipe queue events back to the client over WebSocket
    async def send_to_client():
        try:
            while True:
                msg = await queue.get()
                await websocket.send_text(f"event: message\ndata: {msg}\n\n")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Error sending to WS client: {e}")

    send_task = asyncio.create_task(send_to_client())

    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
            except Exception:
                continue

            msg_id = message.get("id")
            method = message.get("method")
            params = message.get("params", {})

            # 1. Identity Verification
            registered_identity = session_manager.get_identity(session_id)
            if registered_identity != identity:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": f"Security Policy Violation: Identity mismatch for session {session_id} (registered={registered_identity}, request={identity})"
                    }
                }
                log_audit_event(
                    identity=identity,
                    session_id=session_id,
                    tool=params.get("name") if method == "tools/call" else None,
                    args=params.get("arguments") if method == "tools/call" else None,
                    decision="block",
                    reason=f"Session identity pollution mismatch (registered={registered_identity}, request={identity})",
                    reason_codes=["IDENTITY_MISMATCH"],
                    risk_score=1.0
                )
                await queue.put(json.dumps(err_resp))
                continue

            # 2. Circuit Breaker Check
            if circuit_breaker.is_suspended(session_id):
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": "Security Policy Violation: Session suspended due to repeated security flags."
                    }
                }
                log_audit_event(
                    identity=identity,
                    session_id=session_id,
                    tool=params.get("name") if method == "tools/call" else None,
                    args=params.get("arguments") if method == "tools/call" else None,
                    decision="block",
                    reason="Session suspended by circuit breaker.",
                    reason_codes=["SESSION_SUSPENDED"],
                    risk_score=1.0
                )
                await queue.put(json.dumps(err_resp))
                continue

            # 3. Policy Engine Enforcement
            if method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})

                policy_engine.policy = load_policy()
                result = policy_engine.evaluate(identity, tool_name, tool_args)

                log_audit_event(
                    identity=identity,
                    session_id=session_id,
                    tool=tool_name,
                    args=tool_args,
                    decision=result.decision.value,
                    reason=result.reason,
                    reason_codes=result.reason_codes,
                    risk_score=result.risk_score
                )

                if result.decision == Decision.BLOCK:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32602,
                            "message": f"Security Policy Violation: {result.reason}"
                        }
                    }
                    await queue.put(json.dumps(err_resp))
                    continue

            # 4. Message Forwarding
            proc_active = session_manager.processes.get(session_id)
            if proc_active:
                try:
                    proc_active.stdin.write(json.dumps(message).encode() + b"\n")
                    await proc_active.stdin.drain()
                except Exception as e:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32099,
                            "message": f"Error writing to stdio backend process: {e}"
                        }
                    }
                    await queue.put(json.dumps(err_resp))
            elif get_real_server_url():
                backend_url = session_manager.backend_urls.get(session_id)
                if not backend_url:
                    for _ in range(20):
                        backend_url = session_manager.backend_urls.get(session_id)
                        if backend_url:
                            break
                        await asyncio.sleep(0.1)

                if backend_url:
                    try:
                        if http_client:
                            resp = await http_client.post(backend_url, json=message, timeout=10.0)
                            if resp.status_code != 202:
                                err_resp = {
                                    "jsonrpc": "2.0",
                                    "id": msg_id,
                                    "error": {
                                        "code": -32099,
                                        "message": f"Backend server returned status code {resp.status_code}"
                                    }
                                }
                                await queue.put(json.dumps(err_resp))
                    except Exception as e:
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32099,
                                "message": f"Error proxying request to backend: {e}"
                            }
                        }
                        await queue.put(json.dumps(err_resp))
                else:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32099,
                            "message": "Backend session initialization not ready"
                        }
                    }
                    await queue.put(json.dumps(err_resp))
            else:
                # Mock execution fallback
                if method == "tools/call":
                    tool_name = params.get("name")
                    tool_args = params.get("arguments", {})
                    asyncio.create_task(mock_execute_tool(session_id, identity, msg_id, tool_name, tool_args))
                elif method == "initialize":
                    resp_data = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "serverInfo": {
                                "name": "mcp-policy-gateway-mock",
                                "version": "1.0.0"
                            }
                        }
                    }
                    await queue.put(json.dumps(resp_data))
                elif method == "tools/list":
                    policy_engine.policy = load_policy()
                    all_tools = [
                        {"name": "read_file", "description": "Read file content"},
                        {"name": "write_file", "description": "Write file content"},
                        {"name": "list_directory", "description": "List directory content"},
                        {"name": "execute_command", "description": "Run shell command"}
                    ]
                    tool_policy = policy_engine.policy.identities.get(identity)
                    allowed_names = set(tool_policy.allowed_tools) if tool_policy else set()
                    filtered = [t for t in all_tools if t["name"] in allowed_names]
                    resp_data = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "tools": filtered
                        }
                    }
                    await queue.put(json.dumps(resp_data))
                else:
                    resp_data = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {}
                    }
                    await queue.put(json.dumps(resp_data))
    except WebSocketDisconnect:
        pass
    finally:
        send_task.cancel()
        if backend_task:
            backend_task.cancel()
        if stderr_task:
            stderr_task.cancel()
        session_manager.remove_session(session_id)
