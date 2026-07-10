import os
import json
import asyncio
import shlex
from typing import Dict, Any, List, Optional
import httpx

from security.policy_engine import PydanticPolicyEngine, GatewayPolicy
from security.output_guard import scan_output_text, extract_text_from_result
from gateway.state import POLICY_PATH, AUDIT_LOG_PATH, LOG_PATH, session_manager, circuit_breaker, log_audit_event

# Configuration
def get_real_server_url() -> str:
    return os.environ.get("FW_REAL_SERVER_URL", "").strip()

def get_real_server_cmd() -> Optional[List[str]]:
    cmd_str = os.environ.get("FW_REAL_SERVER_CMD", "").strip()
    if not cmd_str:
        return None
    if cmd_str.startswith("[") and cmd_str.endswith("]"):
        try:
            return json.loads(cmd_str)
        except Exception:
            pass
    return shlex.split(cmd_str)

# Load policy helper
def load_policy() -> GatewayPolicy:
    if os.path.exists(POLICY_PATH):
        try:
            with open(POLICY_PATH, "r") as f:
                data = json.load(f)
                return GatewayPolicy.model_validate(data)
        except Exception as e:
            print(f"Error loading policy_v2.json: {e}")
    return GatewayPolicy(identities={})

# Shared Policy Engine
policy_engine = PydanticPolicyEngine(load_policy())

async def log_proc_stderr(proc: asyncio.subprocess.Process):
    try:
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            err_str = line.decode().strip()
            if err_str:
                print(f"[Backend Stderr]: {err_str}")
    except Exception:
        pass

async def listen_to_stdio_backend(session_id: str, identity: str, proc: asyncio.subprocess.Process):
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            line_str = line.decode().strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except Exception:
                q = session_manager.get_queue(session_id)
                if q:
                    await q.put(line_str)
                continue

            msg_id = msg.get("id")

            # Intercept tools/list response to filter allowed tools
            if isinstance(msg.get("result"), dict) and msg["result"].get("tools"):
                policy_engine.policy = load_policy()
                tool_policy = policy_engine.policy.identities.get(identity)
                allowed = set(tool_policy.allowed_tools) if tool_policy else set()
                filtered = [t for t in msg["result"]["tools"] if t.get("name") in allowed]
                msg["result"]["tools"] = filtered
                line_str = json.dumps(msg)

            # Intercept tools/call response
            is_tool_result = (
                isinstance(msg.get("id"), (str, int))
                and isinstance(msg.get("result"), dict)
                and (
                    "content" in msg["result"]
                    or "structuredContent" in msg["result"]
                    or "text" in msg["result"]
                )
            )

            if is_tool_result:
                text_blob = extract_text_from_result(msg["result"])
                reason_codes, snippets = scan_output_text(text_blob)

                if reason_codes:
                    suspended = circuit_breaker.record_flag(session_id)

                    with open(LOG_PATH, "a") as log:
                        log.write(
                            f"[OUTPUT_RISK] mode=block codes={reason_codes} snippets={snippets} session={session_id}\n"
                        )

                    log_audit_event(
                        identity=identity,
                        session_id=session_id,
                        tool="PROXIED_TOOL_RESPONSE",
                        args=None,
                        decision="block" if suspended else "flag",
                        reason=f"Suspicious tool output blocked: {reason_codes}",
                        reason_codes=reason_codes,
                        risk_score=0.8
                    )

                    blocked_msg = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32603,
                            "message": "Security Policy Violation: Suspicious tool output blocked"
                        }
                    }
                    line_str = json.dumps(blocked_msg)
                else:
                    log_audit_event(
                        identity=identity,
                        session_id=session_id,
                        tool="PROXIED_TOOL_RESPONSE",
                        args=None,
                        decision="allow",
                        risk_score=0.0
                    )
                    line_str = json.dumps(msg)

            q = session_manager.get_queue(session_id)
            if q:
                await q.put(line_str)
    except Exception as e:
        print(f"Error in stdio backend listener: {e}")

async def listen_to_backend_stream(session_id: str, identity: str, response: httpx.Response):
    try:
        current_event = None
        async for line in response.aiter_lines():
            line = line.strip()
            if not line:
                continue
            
            if line.startswith("event:"):
                current_event = line.split("event:", 1)[1].strip()
            elif line.startswith("data:"):
                data_val = line.split("data:", 1)[1].strip()
                
                if current_event == "endpoint":
                    session_manager.backend_urls[session_id] = f"{get_real_server_url()}{data_val}"
                elif current_event == "message":
                    try:
                        msg = json.loads(data_val)
                    except Exception:
                        q = session_manager.get_queue(session_id)
                        if q:
                            await q.put(data_val)
                        continue

                    msg_id = msg.get("id")

                    # Intercept tools/list response to filter allowed tools
                    if msg.get("result", {}).get("tools"):
                        policy_engine.policy = load_policy()
                        tool_policy = policy_engine.policy.identities.get(identity)
                        allowed = set(tool_policy.allowed_tools) if tool_policy else set()
                        filtered = [t for t in msg["result"]["tools"] if t.get("name") in allowed]
                        msg["result"]["tools"] = filtered
                        data_val = json.dumps(msg)

                    # Intercept tools/call response
                    is_tool_result = (
                        isinstance(msg.get("id"), (str, int))
                        and isinstance(msg.get("result"), dict)
                        and (
                            "content" in msg["result"]
                            or "structuredContent" in msg["result"]
                            or "text" in msg["result"]
                        )
                    )

                    if is_tool_result:
                        text_blob = extract_text_from_result(msg["result"])
                        reason_codes, snippets = scan_output_text(text_blob)

                        if reason_codes:
                            suspended = circuit_breaker.record_flag(session_id)

                            with open(LOG_PATH, "a") as log:
                                log.write(
                                    f"[OUTPUT_RISK] mode=block codes={reason_codes} snippets={snippets} session={session_id}\n"
                                )

                            log_audit_event(
                                identity=identity,
                                session_id=session_id,
                                tool="PROXIED_TOOL_RESPONSE",
                                args=None,
                                decision="block" if suspended else "flag",
                                reason=f"Suspicious tool output blocked: {reason_codes}",
                                reason_codes=reason_codes,
                                risk_score=0.8
                            )

                            blocked_msg = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32603,
                                    "message": "Security Policy Violation: Suspicious tool output blocked"
                                }
                            }
                            data_val = json.dumps(blocked_msg)
                        else:
                            log_audit_event(
                                identity=identity,
                                session_id=session_id,
                                tool="PROXIED_TOOL_RESPONSE",
                                args=None,
                                decision="allow",
                                risk_score=0.0
                            )
                            data_val = json.dumps(msg)

                    q = session_manager.get_queue(session_id)
                    if q:
                        await q.put(data_val)
            elif line.startswith(":"):
                q = session_manager.get_queue(session_id)
                if q:
                    await q.put(line)
    except Exception as e:
        print(f"Error in backend listener: {e}")
    finally:
        await response.aclose()
