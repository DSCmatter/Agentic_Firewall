import subprocess
import json
import time

def test_mcp_wrapper():
    # Start your wrapper
    proc = subprocess.Popen(
        ["python", "mcp_governor.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    time.sleep(2)  # Let it start
    
    print("Testing MCP Security Wrapper\n")
    
    # Test 1: Allowed operation
    print("Test 1: Allowed operation (list_directory)")
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "list_directory",
            "arguments": {"path": "D:/Coding"}
        }
    }
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    time.sleep(1)
    
    # Test 2: Blocked tool
    print("\nTest 2: Blocked tool (create_directory)")
    request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "create_directory",
            "arguments": {"path": "D:/Coding/newdir"}
        }
    }
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    time.sleep(1)
    
    # Test 3: Path traversal
    print("\nTest 3: Path traversal attack")
    request = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "D:/Coding/../../secrets.txt"}
        }
    }
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    time.sleep(1)
    
    # Test 4: Outside sandbox
    print("\nTest 4: Outside sandbox")
    request = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "list_directory",
            "arguments": {"path": "C:/Windows"}
        }
    }
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    time.sleep(1)
    
    print("\n" + "="*50)
    print("Check threat_log.txt for detailed results")
    print("="*50)
    
    proc.terminate()

if __name__ == "__main__":
    test_mcp_wrapper()