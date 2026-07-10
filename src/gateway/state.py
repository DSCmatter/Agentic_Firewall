import os
import json
import datetime
import asyncio
from typing import Dict, Any, List, Optional

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.path.join(SCRIPT_DIR, "policy_v2.json")
AUDIT_LOG_PATH = os.path.join(SCRIPT_DIR, "gateway_audit.log")
LOG_PATH = os.path.join(SCRIPT_DIR, "threat_log.txt")

# Circuit Breaker
class CircuitBreaker:
    def __init__(self, max_flags: int = 3):
        self.max_flags = max_flags
        self.flags: Dict[str, int] = {}
        self.suspended_sessions: set[str] = set()

    def record_flag(self, session_id: str) -> bool:
        if session_id in self.suspended_sessions:
            return True
        self.flags[session_id] = self.flags.get(session_id, 0) + 1
        if self.flags[session_id] >= self.max_flags:
            self.suspended_sessions.add(session_id)
            return True
        return False

    def is_suspended(self, session_id: str) -> bool:
        return session_id in self.suspended_sessions

circuit_breaker = CircuitBreaker()

# Session Manager
class SessionManager:
    def __init__(self):
        self.queues: Dict[str, asyncio.Queue] = {}
        self.identities: Dict[str, str] = {}
        self.backend_urls: Dict[str, str] = {}
        self.processes: Dict[str, asyncio.subprocess.Process] = {}

    def create_session(self, session_id: str, identity: str) -> asyncio.Queue:
        q = asyncio.Queue()
        self.queues[session_id] = q
        self.identities[session_id] = identity
        return q

    def get_queue(self, session_id: str) -> Optional[asyncio.Queue]:
        return self.queues.get(session_id)

    def get_identity(self, session_id: str) -> str:
        return self.identities.get(session_id, "anonymous")

    def remove_session(self, session_id: str):
        self.queues.pop(session_id, None)
        self.identities.pop(session_id, None)
        self.backend_urls.pop(session_id, None)
        proc = self.processes.pop(session_id, None)
        if proc:
            async def terminate_proc():
                try:
                    proc.terminate()
                    await proc.wait()
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            asyncio.create_task(terminate_proc())

session_manager = SessionManager()

# Logger
def log_audit_event(
    identity: str,
    session_id: str,
    tool: Optional[str],
    args: Any,
    decision: str,
    reason: Optional[str] = None,
    reason_codes: Optional[List[str]] = None,
    risk_score: float = 0.0,
):
    if reason_codes is None:
        reason_codes = []
    event = {
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "identity": identity,
        "session_id": session_id,
        "tool": tool,
        "arguments": args,
        "decision": decision,
        "reason": reason,
        "reason_codes": reason_codes,
        "risk_score": risk_score,
    }
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
