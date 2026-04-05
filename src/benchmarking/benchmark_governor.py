import argparse
import importlib.util
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple


def _percentile(sorted_vals: List[float], p: float) -> float:
    """Return percentile value from a pre-sorted list (ms)."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    rank = (len(sorted_vals) - 1) * (p / 100.0)
    low = int(rank)
    high = min(low + 1, len(sorted_vals) - 1)
    weight = rank - low
    return sorted_vals[low] * (1.0 - weight) + sorted_vals[high] * weight


def _summarize(
    latencies_ms: List[float], total_seconds: float, label: str
) -> Dict[str, Any]:
    """Build standard benchmark summary metrics."""
    if not latencies_ms:
        return {
            "label": label,
            "count": 0,
            "total_seconds": total_seconds,
            "throughput_rps": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
        }

    vals = sorted(latencies_ms)
    count = len(vals)
    throughput = count / total_seconds if total_seconds > 0 else 0.0

    return {
        "label": label,
        "count": count,
        "total_seconds": total_seconds,
        "throughput_rps": throughput,
        "min_ms": vals[0],
        "max_ms": vals[-1],
        "mean_ms": statistics.fmean(vals),
        "median_ms": statistics.median(vals),
        "p50_ms": _percentile(vals, 50),
        "p95_ms": _percentile(vals, 95),
        "p99_ms": _percentile(vals, 99),
    }


def _print_summary(summary: Dict[str, Any]) -> None:
    print(f"\n=== {summary['label']} ===")
    print(f"count          : {summary['count']}")
    print(f"total_seconds  : {summary['total_seconds']:.4f}")
    print(f"throughput_rps : {summary['throughput_rps']:.2f}")
    print(f"min_ms         : {summary['min_ms']:.4f}")
    print(f"max_ms         : {summary['max_ms']:.4f}")
    print(f"mean_ms        : {summary['mean_ms']:.4f}")
    print(f"median_ms      : {summary['median_ms']:.4f}")
    print(f"p50_ms         : {summary['p50_ms']:.4f}")
    print(f"p95_ms         : {summary['p95_ms']:.4f}")
    print(f"p99_ms         : {summary['p99_ms']:.4f}")


def _safe_json_loads(line: str) -> Dict[str, Any]:
    try:
        return json.loads(line)
    except Exception:
        return {}


def load_governor_module(governor_path: str):
    spec = importlib.util.spec_from_file_location(
        "mcp_governor_bench_target", governor_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from path: {governor_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_cases(sandbox_path: str) -> List[Tuple[str, Dict[str, Any]]]:
    allowed_path = os.path.normpath(os.path.join(sandbox_path, "threat_log.txt"))
    traversal_path = os.path.normpath(
        os.path.join(sandbox_path, "..", "..", "secrets.txt")
    )

    return [
        (
            "allowed_read_file",
            {
                "name": "read_file",
                "arguments": {"path": allowed_path},
            },
        ),
        (
            "blocked_tool",
            {
                "name": "create_directory",
                "arguments": {"path": os.path.join(sandbox_path, "newdir")},
            },
        ),
        (
            "blocked_traversal",
            {
                "name": "read_file",
                "arguments": {"path": traversal_path},
            },
        ),
    ]


def run_direct_benchmark(
    governor_path: str, iterations: int, warmup: int, sandbox_path: str
) -> Dict[str, Any]:
    mod = load_governor_module(governor_path)

    if not hasattr(mod, "validate_args") or not hasattr(mod, "ALLOWED_TOOLS"):
        raise RuntimeError(
            "Target module is missing expected symbols: validate_args or ALLOWED_TOOLS"
        )

    cases = build_cases(sandbox_path)
    case_latencies: Dict[str, List[float]] = {name: [] for name, _ in cases}
    case_outcomes: Dict[str, Dict[str, int]] = {
        name: {"allowed": 0, "blocked": 0} for name, _ in cases
    }

    # Warmup
    for _ in range(max(0, warmup)):
        for _, payload in cases:
            tool_name = payload["name"]
            args = payload["arguments"]
            if tool_name in mod.ALLOWED_TOOLS:
                mod.validate_args(tool_name, args)

    start_all = time.perf_counter()

    for _ in range(iterations):
        for case_name, payload in cases:
            tool_name = payload["name"]
            args = payload["arguments"]

            t0 = time.perf_counter()
            if tool_name not in mod.ALLOWED_TOOLS:
                is_allowed = False
            else:
                is_valid, _ = mod.validate_args(tool_name, args)
                is_allowed = bool(is_valid)
            t1 = time.perf_counter()

            case_latencies[case_name].append((t1 - t0) * 1000.0)
            if is_allowed:
                case_outcomes[case_name]["allowed"] += 1
            else:
                case_outcomes[case_name]["blocked"] += 1

    end_all = time.perf_counter()
    total_seconds = end_all - start_all

    summaries = {}
    total_latencies = []
    for name, vals in case_latencies.items():
        summaries[name] = _summarize(vals, total_seconds, f"direct::{name}")
        total_latencies.extend(vals)

    overall = _summarize(total_latencies, total_seconds, "direct::overall")

    return {
        "mode": "direct",
        "iterations": iterations,
        "warmup": warmup,
        "governor_path": governor_path,
        "sandbox_path": sandbox_path,
        "overall": overall,
        "cases": summaries,
        "outcomes": case_outcomes,
    }


def _start_subprocess(governor_path: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, governor_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def run_subprocess_benchmark(
    governor_path: str,
    iterations: int,
    warmup: int,
    sandbox_path: str,
    startup_wait_s: float,
) -> Dict[str, Any]:
    cases = build_cases(sandbox_path)
    proc = _start_subprocess(governor_path)
    if proc.stdin is None or proc.stdout is None:
        raise RuntimeError("Failed to open subprocess pipes.")

    # Give the wrapper time to start MCP server.
    time.sleep(max(0.0, startup_wait_s))

    req_id = 1
    case_latencies: Dict[str, List[float]] = {name: [] for name, _ in cases}
    case_outcomes: Dict[str, Dict[str, int]] = {
        name: {"allowed": 0, "blocked": 0} for name, _ in cases
    }

    def send_and_time(payload: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
        nonlocal req_id
        message = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": payload,
        }
        req_id += 1

        t0 = time.perf_counter()
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()

        # Read until we get one JSON-RPC message with matching id.
        while True:
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError(
                    "Subprocess ended unexpectedly while awaiting response."
                )
            msg = _safe_json_loads(line)
            if msg.get("id") == message["id"]:
                t1 = time.perf_counter()
                return (t1 - t0) * 1000.0, msg

    # Warmup
    for _ in range(max(0, warmup)):
        for _, payload in cases:
            _ = send_and_time(payload)

    start_all = time.perf_counter()

    try:
        for _ in range(iterations):
            for case_name, payload in cases:
                latency_ms, response = send_and_time(payload)
                case_latencies[case_name].append(latency_ms)

                if "error" in response:
                    case_outcomes[case_name]["blocked"] += 1
                else:
                    case_outcomes[case_name]["allowed"] += 1
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    end_all = time.perf_counter()
    total_seconds = end_all - start_all

    summaries = {}
    total_latencies = []
    for name, vals in case_latencies.items():
        summaries[name] = _summarize(vals, total_seconds, f"subprocess::{name}")
        total_latencies.extend(vals)

    overall = _summarize(total_latencies, total_seconds, "subprocess::overall")

    return {
        "mode": "subprocess",
        "iterations": iterations,
        "warmup": warmup,
        "governor_path": governor_path,
        "sandbox_path": sandbox_path,
        "startup_wait_s": startup_wait_s,
        "overall": overall,
        "cases": summaries,
        "outcomes": case_outcomes,
    }


def append_results_json(output_path: str, result: Dict[str, Any]) -> None:
    payload = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        **result,
    }

    existing: List[Dict[str, Any]] = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, list):
                existing = loaded
        except Exception:
            # If file is corrupted or non-JSON, overwrite with fresh list.
            existing = []

    existing.append(payload)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark harness for mcp_governor latency and throughput."
    )
    parser.add_argument(
        "--mode",
        choices=["direct", "subprocess", "both"],
        default="both",
        help="Benchmark mode: direct validate_args only, subprocess end-to-end, or both.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of benchmark iterations per case.",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=100,
        help="Warmup iterations per case before measurement.",
    )
    parser.add_argument(
        "--governor",
        default=os.path.join(os.path.dirname(__file__), "mcp_governor.py"),
        help="Path to mcp_governor.py",
    )
    parser.add_argument(
        "--sandbox",
        default="D:/Coding",
        help="Sandbox path used to generate benchmark payloads.",
    )
    parser.add_argument(
        "--output",
        default=os.path.join(os.path.dirname(__file__), "bench_results.json"),
        help="Path to benchmark JSON output file.",
    )
    parser.add_argument(
        "--startup-wait",
        type=float,
        default=2.0,
        help="Seconds to wait for subprocess mode startup.",
    )

    args = parser.parse_args()

    governor_path = os.path.abspath(args.governor)
    if not os.path.exists(governor_path):
        raise FileNotFoundError(f"Governor file not found: {governor_path}")

    results: List[Dict[str, Any]] = []

    if args.mode in ("direct", "both"):
        direct_result = run_direct_benchmark(
            governor_path=governor_path,
            iterations=args.iterations,
            warmup=args.warmup,
            sandbox_path=args.sandbox,
        )
        results.append(direct_result)

    if args.mode in ("subprocess", "both"):
        subprocess_result = run_subprocess_benchmark(
            governor_path=governor_path,
            iterations=args.iterations,
            warmup=args.warmup,
            sandbox_path=args.sandbox,
            startup_wait_s=args.startup_wait,
        )
        results.append(subprocess_result)

    for result in results:
        print("\n" + "=" * 72)
        print(f"Mode: {result['mode']}")
        _print_summary(result["overall"])
        for case_name, summary in result["cases"].items():
            _print_summary(summary)
        print("\nOutcomes:")
        for case_name, outcome in result["outcomes"].items():
            print(
                f"  {case_name}: allowed={outcome['allowed']} blocked={outcome['blocked']}"
            )

        append_results_json(args.output, result)

    print("\nBenchmark complete.")
    print(f"Results appended to: {os.path.abspath(args.output)}")


if __name__ == "__main__":
    main()
