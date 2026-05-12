"""Regression harness package."""

from __future__ import annotations

from adversary.regression.harness import (
    RegressionRecord,
    RegressionResult,
    run_regression,
    write_junit_xml,
)

__all__ = [
    "RegressionRecord",
    "RegressionResult",
    "run_regression",
    "write_junit_xml",
]
