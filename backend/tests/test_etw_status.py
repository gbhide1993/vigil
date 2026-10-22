"""The ETW availability helpers in core/monitoring_status.py: tier values, the reason text, and the wording of
the report line for a normal install (ETW not running)."""

import pytest

from core import monitoring_status as ms
from core import report_coverage


@pytest.fixture(autouse=True)
def _restore_state():
    tier, reason = ms._file_tier, ms._etw_reason
    yield
    ms._file_tier, ms._etw_reason = tier, reason


@pytest.mark.parametrize("given, expected", [
    ("etw", "etw"), ("native", "native"), ("polling", "polling"),
    ("folders", "polling"), ("", "polling"), ("kernel", "polling"),
])
def test_tier_values_are_normalised(given, expected):
    ms.set_file_watcher_tier(given)
    assert ms.file_watcher_tier() == expected


def test_etw_available_follows_the_tier_and_the_reason_clears_when_it_runs():
    ms.set_file_watcher_tier("native")
    ms.set_etw_unavailable_reason("kernel tracing needs administrator")
    assert not ms.etw_available() and ms.etw_unavailable_reason() == "kernel tracing needs administrator"
    ms.set_file_watcher_tier("etw")
    assert ms.etw_available() and ms.etw_unavailable_reason() is None


def test_a_missing_reason_still_reads_as_a_sentence_when_etw_is_off():
    ms.set_file_watcher_tier("polling")
    ms.set_etw_unavailable_reason(None)
    assert ms.etw_unavailable_reason() == "kernel tracing did not start"


@pytest.mark.parametrize("error, expected", [
    ("Access is denied", "kernel tracing needs administrator"),
    ("administrator privileges required", "kernel tracing needs administrator"),
    ("", "kernel tracing did not start"),
    (None, "kernel tracing did not start"),
    ("session limit reached", "kernel tracing could not start (session limit reached)"),
])
def test_describe_etw_failure(error, expected):
    assert ms.describe_etw_failure(error) == expected


@pytest.mark.parametrize("error", ["AlreadyExist", "The session already exists (AlreadyExist)", "Already exist"])
def test_describe_etw_failure_names_a_stale_session_not_the_raw_error(error):
    text = ms.describe_etw_failure(error)
    assert "still running" in text and "AlreadyExist" not in text


def test_describe_etw_failure_truncates_long_errors():
    assert len(ms.describe_etw_failure("x" * 500)) < 130


def test_report_line_does_not_claim_exact_attribution_or_an_active_kernel_tier():
    line = next(l for l in report_coverage.LINES if l.startswith("Attribution"))
    assert line == "Attribution to an agent is a best guess, based on file location and which agents are running."
    assert not any("ETW" in l or "exact" in l.lower() for l in report_coverage.LINES)
