from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Decision(str, Enum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    BLOCK = "block"


@dataclass
class PolicyResult:
    decision: Decision
    reason: Optional[str] = None
    reason_codes: List[str] = field(default_factory=list)
    risk_score: float = 0.0


class BasicPolicyEngine:
    """
    Minimal engine for current governor integration.
    mode: off|log|challenge|block
    """

    VALID_MODES = {"off", "log", "challenge", "block"}

    def __init__(
        self,
        allow_list: List[str],
        arg_constraints: Dict[str, Dict[str, str]],
        mode: str = "log",
    ) -> None:
        self.allow_list = set(allow_list)
        self.arg_constraints = arg_constraints
        self.mode = mode.lower() if isinstance(mode, str) else "log"
        if self.mode not in self.VALID_MODES:
            self.mode = "log"

    def evaluate(self, context: Dict[str, Any]) -> PolicyResult:
        tool_name = context.get("tool_name")
        tool_args = context.get("tool_args", {})

        # 1) allow-list check
        if tool_name not in self.allow_list:
            return self._decide_violation(
                reason=f"Tool '{tool_name}' is not in allow_list",
                code="TOOL_NOT_ALLOWED",
            )

        # 2) args check (existing logic parity)
        ok, err = self._validate_args(tool_name, tool_args)
        if not ok:
            return self._decide_violation(reason=err, code="ARG_CONSTRAINT_VIOLATION")

        return PolicyResult(decision=Decision.ALLOW)

    def _decide_violation(self, reason: str, code: str) -> PolicyResult:
        if self.mode in ("off", "log"):
            # Safe rollout: log but allow
            return PolicyResult(
                decision=Decision.ALLOW,
                reason=reason,
                reason_codes=[code],
                risk_score=0.3,
            )
        if self.mode == "challenge":
            return PolicyResult(
                decision=Decision.CHALLENGE,
                reason=reason,
                reason_codes=[code],
                risk_score=0.6,
            )
        return PolicyResult(
            decision=Decision.BLOCK, reason=reason, reason_codes=[code], risk_score=1.0
        )

    def _validate_args(
        self, tool_name: str, args: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        if tool_name not in self.arg_constraints:
            return True, None

        rules = self.arg_constraints[tool_name]

        for param, rule in rules.items():
            val = args.get(param)
            if not val:
                continue

            if rule.startswith("SANDBOX:"):
                sandbox_path = rule.split("SANDBOX:", 1)[1].strip()
                sandbox_abs = os.path.abspath(os.path.normpath(sandbox_path))
                val_abs = os.path.abspath(os.path.normpath(str(val)))

                # Robust sandbox containment check
                try:
                    if os.path.commonpath([sandbox_abs, val_abs]) != sandbox_abs:
                        return (
                            False,
                            f"Path '{val}' is outside sandbox '{sandbox_path}'",
                        )
                except ValueError:
                    # Different drives on Windows, etc.
                    return False, f"Path '{val}' is outside sandbox '{sandbox_path}'"

                if ".." in str(val):
                    return False, f"Path traversal detected in '{val}'"

            elif rule.startswith("ALLOW_ONLY:"):
                allowed = [
                    x.strip() for x in rule.split("ALLOW_ONLY:", 1)[1].split(",")
                ]
                if str(val) not in allowed:
                    return False, f"Value '{val}' not in allowed list: {allowed}"

            elif rule.startswith("BLOCK_TERMS:"):
                blocked = [
                    x.strip() for x in rule.split("BLOCK_TERMS:", 1)[1].split(",")
                ]
                for term in blocked:
                    if term and term.lower() in str(val).lower():
                        return False, f"Blocked term '{term}' found in '{val}'"

        return True, None
