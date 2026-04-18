from security.policy_engine import BasicPolicyEngine

engine = BasicPolicyEngine(
    allow_list=["read_file", "list_directory"],
    arg_constraints={"read_file": {"path": "SANDBOX:D:/Coding"}},
    mode="block",
)

cases = [
    {"tool_name": "read_file", "tool_args": {"path": "D:/Coding/a.txt"}},
    {"tool_name": "delete_file", "tool_args": {"path": "D:/Coding/a.txt"}},
    {"tool_name": "read_file", "tool_args": {"path": "D:/Windows/win.ini"}},
]

for c in cases:
    res = engine.evaluate(c)
    print(
        c["tool_name"],
        c["tool_args"]["path"],
        "->",
        res.decision,
        res.reason_codes,
        res.reason,
    )
