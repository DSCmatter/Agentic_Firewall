# Agentic Firewall

**An MCP Security Gateway for Claude Desktop**

Inspired from [Anthropic Research](https://www.anthropic.com/news/disrupting-AI-espionage)

Agentic Firewall is a lightweight security wrapper that intercepts and validates Model Context Protocol (MCP) tool calls, providing enterprise-grade access control for AI agents like Claude.

Here, we have utilized only filesystem, in the future we will also utilize the weather api as experiment and so on...

---

## Features

- **Tool Whitelisting** - Only approved tools can be executed
- **Sandbox Enforcement** - Restrict file operations to specific directories
- **Path Traversal Protection** - Blocks `../` and absolute path attacks
- **Audit Logging** - Complete visibility into allowed/blocked requests
- **Zero Latency** - Transparent proxying with minimal overhead
- **Policy-Driven** - Configure security rules via simple JSON

---

## Installation

### Prerequisites
- Python 3.8+
- Node.js 16+ (for MCP servers)
- Claude Desktop

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/agentic-firewall.git
cd agentic-firewall
```

2. **Install MCP server** (example: filesystem)
```bash
npm install -g @modelcontextprotocol/server-filesystem
```

3. **Configure your policy** (see `policy.json` below)

4. **Update Claude Desktop config**

Edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac):

```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "python",
      "args": ["C:/path/to/agentic-firewall/mcp_governor.py"]
    }
  }
}
```

5. **Restart Claude Desktop**

---

## Configuration

### `policy.json`

Define your security policy in `policy.json`:

```json
{
  "allow_list": [
    "read_file",
    "list_directory",
    "write_file",
    "search_files",
    "get_file_info"
  ],
  "arg_constraints": {
    "read_file": {
      "path": "SANDBOX:D:/Coding"
    },
    "write_file": {
      "path": "SANDBOX:D:/Coding"
    },
    "list_directory": {
      "path": "SANDBOX:D:/Coding"
    }
  },
  "deny_behavior": "block_and_log"
}
```

### Policy Options

#### `allow_list`
Array of tool names that are permitted. Any tool not in this list will be blocked.

#### `arg_constraints`
Validation rules for tool arguments:

| Constraint | Description | Example |
|------------|-------------|---------|
| `SANDBOX:path` | Restricts paths to a specific directory | `"SANDBOX:D:/Coding"` |
| `ALLOW_ONLY:val1,val2` | Only specific values are permitted | `"ALLOW_ONLY:read,write"` |
| `BLOCK_TERMS:term1,term2` | Blocks if argument contains terms | `"BLOCK_TERMS:admin,root"` |

---

## Usage Examples

### Example 1: Allowed Request
**Prompt:** "List all files in D:/Coding"

✅ **Result:** Request forwarded to filesystem server
```
[ALLOWED] Tool: list_directory | Args: {"path": "D:/Coding"}
```

### Example 2: Blocked Tool
**Prompt:** "Create a new directory at D:/Coding/test"

❌ **Result:** Blocked (tool not in allow_list)
```
[BLOCKED] Tool 'create_directory' is not in allow_list | Tool: create_directory | Args: {"path": "D:/Coding/test"}
```

### Example 3: Path Traversal Attack
**Prompt:** "Read the file at D:/Coding/../../../Windows/System32/config/SAM"

❌ **Result:** Blocked (path traversal detected)
```
[BLOCKED] Path traversal detected in 'D:/Coding/../../../Windows/System32/config/SAM' | Tool: read_file | Args: {"path": "D:/Coding/../../../Windows/System32/config/SAM"}
```

### Example 4: Sandbox Violation
**Prompt:** "List files in C:/Windows"

❌ **Result:** Blocked (outside sandbox)
```
[BLOCKED] Path 'C:\Windows' is outside sandbox 'D:\Coding' | Tool: list_directory | Args: {"path": "C:/Windows"}
```

---

## Audit Logging

All requests are logged to `threat_log.txt` in the same directory as the wrapper:

```
[ALLOWED] Tool: list_directory | Args: {"path": "D:/Coding"}
[BLOCKED] Tool 'create_directory' is not in allow_list | Tool: create_directory | Args: {"path": "D:/Coding/test"}
[BLOCKED] Path traversal detected in 'D:/Coding/../../secrets.txt' | Tool: read_file | Args: {"path": "D:/Coding/../../secrets.txt"}
```

### Log Format
- `[ALLOWED]` - Request passed validation and was forwarded
- `[BLOCKED]` - Request violated policy and was denied
- `[ERROR]` - Internal error occurred
- `[CRITICAL]` - Configuration error (e.g., missing policy.json)

---

## Testing

### Manual Testing
```bash
# Test allowed operation
python test_wrapper.py
```

### Test with Claude Desktop
Try these prompts to verify security:

1. ✅ **Allowed:** "List files in D:/Coding"
2. ❌ **Blocked:** "Create directory D:/Coding/test"
3. ❌ **Blocked:** "Read D:/Coding/../../secrets.txt"
4. ❌ **Blocked:** "List files in C:/Windows"

Check `threat_log.txt` after each test.

---

## Architecture

```
┌─────────────────┐
│  Claude Desktop │
└────────┬────────┘
         │
         │ JSON-RPC
         ▼
┌─────────────────────────┐
│  Agentic Firewall       │
│  (mcp_governor.py)      │
│                         │
│  ┌─────────────────┐    │
│  │ Policy Engine   │    │
│  │ - Whitelist     │    │
│  │ - Validation    │    │
│  │ - Sandbox Check │    │
│  └─────────────────┘    │
│                         │
│  ┌─────────────────┐    │
│  │ Audit Logger    │────┼──► threat_log.txt
│  └─────────────────┘    │
└────────┬────────────────┘
         │
         │ Filtered Requests
         ▼
┌─────────────────────────┐
│  MCP Server             │
│  (filesystem/weather)   │
└─────────────────────────┘
```

---

## Security Best Practices

### 1. **Principle of Least Privilege**
Only whitelist tools that are absolutely necessary:
```json
{
  "allow_list": ["read_file", "list_directory"]  // Not write_file
}
```

### 2. **Strict Sandboxing**
Always use `SANDBOX:` constraints for file operations:
```json
{
  "arg_constraints": {
    "read_file": {
      "path": "SANDBOX:/var/app/data"
    }
  }
}
```

### 3. **Regular Audit Reviews**
Monitor `threat_log.txt` for suspicious patterns:
```bash
# Check for repeated blocked attempts
grep "BLOCKED" threat_log.txt | sort | uniq -c
```

### 4. **Defense in Depth**
Combine with OS-level permissions and network isolation.

---

## Troubleshooting

### Issue: "FileNotFoundError: npx not found"
**Solution:** Ensure Node.js is installed and in PATH:
```bash
node --version
npx --version
```

Or update `mcp_governor.py` with full path:
```python
REAL_SERVER_CMD = [
    r"C:\Program Files\nodejs\npx.cmd",
    "-y",
    "@modelcontextprotocol/server-filesystem",
    "D:/Coding"
]
```

### Issue: No logs appearing
**Solution:** Check file permissions and ensure `threat_log.txt` is writable.

### Issue: All requests blocked
**Solution:** Verify `policy.json` exists and contains valid JSON.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
- Inspired by enterprise API gateway patterns
- Community feedback and testing

---

## Related Projects

- [MCP Servers](https://github.com/modelcontextprotocol/servers) - Official MCP server implementations
- [Claude Desktop](https://claude.ai/download) - AI assistant with MCP support

---

<div align="center">
<strong>Secure AI agents. Audit everything. Trust nothing.</strong>
</div>