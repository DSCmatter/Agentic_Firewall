import json
import os
import subprocess
import sys
import threading

from security.output_guard import extract_text_from_result, scan_output_text
from security.policy_engine import BasicPolicyEngine, Decision

# path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(SCRIPT_DIR, "policy.json")
LOG_PATH = os.path.join(SCRIPT_DIR, "threat_log.txt")

# load policy
try:
    with open(POLICY_PATH, "r") as f:
        POLICY = json.load(f)
except FileNotFoundError:
    POLICY = {"allow_list": [], "arg_constraints": {}}
    with open(LOG_PATH, "a") as log:
        log.write("[CRITICAL] policy.json not found. Blocking everything.\n")

ALLOWED_TOOLS = set(POLICY.get("allow_list", []))
ARG_CONSTRAINTS = POLICY.get("arg_constraints", {})

# mode: off|log|challenge|block
POLICY_MODE = os.environ.get("FW_POLICY_MODE", "block").strip().lower()

# tool output guard mode: off|log|block
TOOL_OUTPUT_GUARD_MODE = os.environ.get("FW_TOOL_OUTPUT_GUARD", "log").strip().lower()
if TOOL_OUTPUT_GUARD_MODE not in {"off", "log", "block"}:
    TOOL_OUTPUT_GUARD_MODE = "log"

ENGINE = BasicPolicyEngine(
    allow_list=list(ALLOWED_TOOLS),
    arg_constraints=ARG_CONSTRAINTS,
    mode=POLICY_MODE,
)


def _extract_session_id(message: dict) -> str:
    """
    Best-effort session id extraction from incoming JSON-RPC payload.
    Falls back to a static value when not present.
    """
    sid = message.get("session_id") or message.get("sessionId")
    if isinstance(sid, (str, int)):
        return str(sid)
    return "mcp-session"


# main loop
def handle_client_input(proc):
    """Handle incoming requests from Claude"""
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            message = json.loads(line)

            # Intercept tools/call requests
            if message.get("method") == "tools/call":
                tool_name = message.get("params", {}).get("name")
                tool_args = message.get("params", {}).get("arguments", {})

                result = ENGINE.evaluate(
                    {
                        "tool_name": tool_name,
                        "tool_args": tool_args,
                        "session_id": _extract_session_id(message),
                    }
                )

                # Log policy decision
                with open(LOG_PATH, "a") as log:
                    log.write(
                        f"[POLICY] decision={result.decision.value} "
                        f"tool={tool_name} args={json.dumps(tool_args)} "
                        f"reason={result.reason} codes={result.reason_codes} "
                        f"risk={result.risk_score}\n"
                    )

                if result.decision in (Decision.BLOCK, Decision.CHALLENGE):
                    # challenge currently treated as deny until interactive approval exists
                    err = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32602,
                            "message": f"Security Policy Violation: {result.reason or 'Request denied'}",
                        },
                    }
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()
                    continue

            # Forward to real server (if not blocked)
            proc.stdin.write(line)
            proc.stdin.flush()

        except json.JSONDecodeError:
            # Forward non-JSON lines as-is
            proc.stdin.write(line)
            proc.stdin.flush()
        except Exception as e:
            with open(LOG_PATH, "a") as log:
                log.write(f"[ERROR] Exception in handle_client_input: {e}\n")


def handle_server_output(proc):
    """Forward responses from real server to Claude, with optional filtering"""
    while True:
        try:
            line = proc.stdout.readline()
            if not line:
                break

            try:
                msg = json.loads(line)

                # Filter tools/list to only show allowed tools
                if msg.get("result", {}).get("tools"):
                    filtered_tools = [
                        t
                        for t in msg["result"]["tools"]
                        if t.get("name") in ALLOWED_TOOLS
                    ]
                    msg["result"]["tools"] = filtered_tools

                is_tool_result = (
                    isinstance(msg.get("id"), (str, int))
                    and isinstance(msg.get("result"), dict)
                    and (
                        "content" in msg["result"]
                        or "structuredContent" in msg["result"]
                        or "text" in msg["result"]
                    )
                )

                # Output guard (log/block)
                if TOOL_OUTPUT_GUARD_MODE != "off" and is_tool_result:
                    text_blob = extract_text_from_result(msg.get("result", {}))
                    reason_codes, snippets = scan_output_text(text_blob)

                    if reason_codes:
                        with open(LOG_PATH, "a") as log:
                            log.write(
                                f"[OUTPUT_RISK] mode={TOOL_OUTPUT_GUARD_MODE} "
                                f"codes={reason_codes} snippets={snippets}\n"
                            )

                        if TOOL_OUTPUT_GUARD_MODE == "block":
                            blocked = {
                                "jsonrpc": "2.0",
                                "id": msg.get("id"),
                                "error": {
                                    "code": -32603,
                                    "message": "Security Policy Violation: Suspicious tool output blocked",
                                },
                            }
                            line = json.dumps(blocked) + "\n"
                        else:
                            line = json.dumps(msg) + "\n"
                    else:
                        line = json.dumps(msg) + "\n"
                else:
                    line = json.dumps(msg) + "\n"

            except (json.JSONDecodeError, KeyError, TypeError):
                pass  # Not JSON-RPC message shape, forward as-is

            sys.stdout.write(line)
            sys.stdout.flush()

        except Exception as e:
            with open(LOG_PATH, "a") as log:
                log.write(f"[ERROR] Exception in handle_server_output: {e}\n")


if __name__ == "__main__":
    server_cfg = POLICY.get("server", {})
    server_command = server_cfg.get("command", r"C:/Program Files/nodejs/npx.cmd")
    server_args = server_cfg.get(
        "args", ["-y", "@modelcontextprotocol/server-filesystem"]
    )
    server_sandbox_root = server_cfg.get("sandbox_root", "D:/Coding")

    REAL_SERVER_CMD = [
        server_command,
        *server_args,
        server_sandbox_root,
    ]

    with open(LOG_PATH, "a") as log:
        log.write(
            f"[STARTUP] policy_mode={POLICY_MODE} "
            f"tool_output_guard_mode={TOOL_OUTPUT_GUARD_MODE} "
            f"real_server_cmd={REAL_SERVER_CMD}\n"
        )

    # Start the real filesystem server
    proc = subprocess.Popen(
        REAL_SERVER_CMD,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    # Start bidirectional communication threads
    t1 = threading.Thread(target=handle_client_input, args=(proc,), daemon=True)
    t2 = threading.Thread(target=handle_server_output, args=(proc,), daemon=True)

    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        with open(LOG_PATH, "a") as log:
            log.write("[INFO] Wrapper shutting down\n")
        proc.terminate()
