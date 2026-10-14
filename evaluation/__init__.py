"""Evaluation and Benchmarking Package for Multi-Agent SOC Analyst.

Exports:
    run_full_benchmark: Executes end-to-end evaluation suite across test scenarios.
    run_single_benchmark_case: Evaluates a single scenario.
"""

from evaluation.benchmark import run_full_benchmark, run_single_benchmark_case

__all__ = ["run_full_benchmark", "run_single_benchmark_case"]
