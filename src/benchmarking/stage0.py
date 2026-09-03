"""Installed entry point for the complete Stage 0 security benchmark."""

from benchmarking.attack_harness import main as run_benchmark


def main() -> None:
    """Start the local services, execute the benchmark, and always clean up."""
    run_benchmark()
