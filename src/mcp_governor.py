import sys
import json
import subprocess
import threading
import os

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

ALLOWED_TOOLS = set(POLICY["allow_list"])
ARG_CONSTRAINTS = POLICY.get("arg_constraints", {})

# filesystem server command
REAL_SERVER_CMD = [
    r"C:/Program Files/nodejs/npx.cmd",  # Use your actual path
    "-y",
    "@modelcontextprotocol/server-filesystem",
    "D:/Coding" 
]
# validation logic
def validate_args(tool_name, args):
    """Validate tool arguments against policy constraints"""
    if tool_name not in ARG_CONSTRAINTS:
        return True, None
    
    rules = ARG_CONSTRAINTS[tool_name]
    
    for param, rule in rules.items():
        val = args.get(param)
        if not val:
            continue
        
        # Handle SANDBOX constraint
        if rule.startswith("SANDBOX:"):
            sandbox_path = rule.split("SANDBOX:")[1]
            # Normalize paths for comparison
            sandbox_path = os.path.normpath(sandbox_path)
            val_path = os.path.normpath(val)
            
            # Check if the requested path is within the sandbox
            try:
                # Get absolute paths
                sandbox_abs = os.path.abspath(sandbox_path)
                val_abs = os.path.abspath(val_path)
                
                # Check if val_abs starts with sandbox_abs
                if not val_abs.startswith(sandbox_abs):
                    return False, f"Path '{val}' is outside sandbox '{sandbox_path}'"
                    
                # Additional check: prevent path traversal attacks
                if ".." in val:
                    return False, f"Path traversal detected in '{val}'"
                    
            except Exception as e:
                return False, f"Path validation error: {e}"
        
        # Handle ALLOW_ONLY constraint
        elif rule.startswith("ALLOW_ONLY:"):
            allowed = rule.split("ALLOW_ONLY:")[1].split(",")
            if val not in allowed:
                return False, f"Value '{val}' not in allowed list: {allowed}"
        
        # Handle BLOCK_TERMS constraint
        elif rule.startswith("BLOCK_TERMS:"):
            blocked = rule.split("BLOCK_TERMS:")[1].split(",")
            for term in blocked:
                if term.lower() in str(val).lower():
                    return False, f"Blocked term '{term}' found in '{val}'"
    
    return True, None

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
                
                # Check if tool is allowed
                if tool_name not in ALLOWED_TOOLS:
                    reason = f"Tool '{tool_name}' is not in allow_list"
                    
                    # Log the block
                    with open(LOG_PATH, "a") as log:
                        log.write(f"[BLOCKED] {reason} | Tool: {tool_name} | Args: {json.dumps(tool_args)}\n")
                    
                    # Send error response to Claude
                    err = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32602,
                            "message": f"Security Policy Violation: {reason}"
                        }
                    }
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()
                    continue
                
                # Validate arguments
                is_valid, validation_error = validate_args(tool_name, tool_args)
                if not is_valid:
                    # Log the block
                    with open(LOG_PATH, "a") as log:
                        log.write(f"[BLOCKED] {validation_error} | Tool: {tool_name} | Args: {json.dumps(tool_args)}\n")
                    
                    # Send error response to Claude
                    err = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "error": {
                            "code": -32602,
                            "message": f"Security Policy Violation: {validation_error}"
                        }
                    }
                    sys.stdout.write(json.dumps(err) + "\n")
                    sys.stdout.flush()
                    continue
                
                # Log allowed access
                with open(LOG_PATH, "a") as log:
                    log.write(f"[ALLOWED] Tool: {tool_name} | Args: {json.dumps(tool_args)}\n")
            
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
            
            # Parse and potentially filter tools/list responses
            try:
                msg = json.loads(line)
                
                # Filter tools/list to only show allowed tools
                if msg.get("result", {}).get("tools"):
                    filtered_tools = [
                        t for t in msg["result"]["tools"]
                        if t.get("name") in ALLOWED_TOOLS
                    ]
                    msg["result"]["tools"] = filtered_tools
                    line = json.dumps(msg) + "\n"
            except (json.JSONDecodeError, KeyError):
                pass  # Not a tools/list response, forward as-is
            
            sys.stdout.write(line)
            sys.stdout.flush()
            
        except Exception as e:
            with open(LOG_PATH, "a") as log:
                log.write(f"[ERROR] Exception in handle_server_output: {e}\n")

if __name__ == "__main__":
    # Start the real filesystem server
    proc = subprocess.Popen(
        REAL_SERVER_CMD,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1  # Line buffered
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