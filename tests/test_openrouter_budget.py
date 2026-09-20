"""Tests for OpenRouter budget enforcement."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from decimal import Decimal
from pathlib import Path

import pytest

from openrouter_budget import (
    BudgetExceededError,
    BudgetLimits,
    OpenRouterBudgetGuard,
    SilentFallbackError,
)

CONTROLLER_DIR = Path(__file__).resolve().parents[1] / "controller"


def _limits() -> BudgetLimits:
    return BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50"))


def _authorize_script(ledger_path: Path, ready_path: Path, amount: str = "5") -> str:
    return f"""
from decimal import Decimal
from pathlib import Path
from openrouter_budget import BudgetLimits, OpenRouterBudgetGuard
guard = OpenRouterBudgetGuard(
    BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50")),
    ledger_path=Path({str(ledger_path)!r}),
)
guard.authorize_fallback(
    run_id="run-1",
    reason="provider-limit",
    estimated_cost_usd=Decimal({amount!r}),
    explicit_fallback=True,
)
Path({str(ready_path)!r}).write_text("ok")
import time
time.sleep(60)
"""


def test_openrouter_spend_requires_explicit_budget_decision() -> None:
    guard = OpenRouterBudgetGuard(BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50")))
    with pytest.raises(SilentFallbackError):
        guard.authorize_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("1"),
            explicit_fallback=False,
        )


def test_openrouter_fallback_records_remaining_budget(tmp_path) -> None:
    guard = OpenRouterBudgetGuard(_limits(), ledger_path=tmp_path / "openrouter-budget-ledger.json")
    auth = guard.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("1"),
        explicit_fallback=True,
    )
    assert auth.reason == "provider-limit"
    assert auth.remaining_run_budget_usd == Decimal("4")
    guard.record_spend(auth)
    assert guard.ledger.spent_for_run("run-1") == Decimal("1")


def test_openrouter_budget_enforces_per_run_limit(tmp_path) -> None:
    guard = OpenRouterBudgetGuard(
        BudgetLimits(per_run_usd=Decimal("1"), monthly_usd=Decimal("50")),
        ledger_path=tmp_path / "openrouter-budget-ledger.json",
    )
    with pytest.raises(BudgetExceededError):
        guard.authorize_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("2"),
            explicit_fallback=True,
        )


def test_in_memory_authorize_is_unavailable() -> None:
    guard = OpenRouterBudgetGuard(_limits())
    with pytest.raises(ValueError, match="ledger_path"):
        guard.authorize_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("1"),
            explicit_fallback=True,
        )


def test_second_authorize_against_remaining_budget_fails(tmp_path) -> None:
    limits = BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50"))
    path = tmp_path / "openrouter-budget-ledger.json"
    first = OpenRouterBudgetGuard(limits, ledger_path=path)
    first.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("5"),
        explicit_fallback=True,
    )
    second = OpenRouterBudgetGuard(limits, ledger_path=path)
    with pytest.raises(BudgetExceededError):
        second.authorize_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("1"),
            explicit_fallback=True,
        )


def test_record_spend_settles_reservation_without_double_count(tmp_path) -> None:
    limits = BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50"))
    path = tmp_path / "openrouter-budget-ledger.json"
    guard = OpenRouterBudgetGuard(limits, ledger_path=path)
    auth = guard.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("2"),
        explicit_fallback=True,
    )
    guard.record_spend(auth)
    assert guard.ledger.spent_for_run("run-1") == Decimal("2")
    later = OpenRouterBudgetGuard(limits, ledger_path=path)
    later.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("3"),
        explicit_fallback=True,
    )
    with pytest.raises(BudgetExceededError):
        later.authorize_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("1"),
            explicit_fallback=True,
        )


def test_crash_before_settle_holds_reservation(tmp_path) -> None:
    limits = BudgetLimits(per_run_usd=Decimal("5"), monthly_usd=Decimal("50"))
    path = tmp_path / "openrouter-budget-ledger.json"
    first = OpenRouterBudgetGuard(limits, ledger_path=path)
    auth = first.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("4"),
        explicit_fallback=True,
    )
    revived = OpenRouterBudgetGuard(limits, ledger_path=path)
    with pytest.raises(BudgetExceededError):
        revived.authorize_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("2"),
            explicit_fallback=True,
        )
    revived.record_spend(auth)
    assert revived.ledger.spent_for_run("run-1") == Decimal("4")
    revived.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("1"),
        explicit_fallback=True,
    )


def test_two_os_processes_cannot_both_authorize(tmp_path) -> None:
    path = tmp_path / "openrouter-budget-ledger.json"
    ready = tmp_path / "ready"
    child_script = tmp_path / "child.py"
    child_script.write_text(_authorize_script(path, ready))
    env = {**os.environ, "PYTHONPATH": str(CONTROLLER_DIR)}
    proc = subprocess.Popen([sys.executable, str(child_script)], env=env)
    try:
        deadline = time.time() + 10
        while time.time() < deadline and not ready.is_file():
            if proc.poll() is not None:
                raise AssertionError(f"child exited before authorize: {proc.returncode}")
            time.sleep(0.05)
        assert ready.is_file(), "child did not persist authorization"
        second = OpenRouterBudgetGuard(_limits(), ledger_path=path)
        with pytest.raises(BudgetExceededError):
            second.authorize_fallback(
                run_id="run-1",
                reason="provider-limit",
                estimated_cost_usd=Decimal("1"),
                explicit_fallback=True,
            )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_sigkill_after_authorize_holds_reservation(tmp_path) -> None:
    path = tmp_path / "openrouter-budget-ledger.json"
    ready = tmp_path / "ready"
    child_script = tmp_path / "child.py"
    child_script.write_text(_authorize_script(path, ready, "4"))
    env = {**os.environ, "PYTHONPATH": str(CONTROLLER_DIR)}
    proc = subprocess.Popen([sys.executable, str(child_script)], env=env)
    try:
        deadline = time.time() + 10
        while time.time() < deadline and not ready.is_file():
            if proc.poll() is not None:
                raise AssertionError(f"child exited before authorize: {proc.returncode}")
            time.sleep(0.05)
        assert ready.is_file()
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    revived = OpenRouterBudgetGuard(_limits(), ledger_path=path)
    with pytest.raises(BudgetExceededError):
        revived.authorize_fallback(
            run_id="run-1",
            reason="provider-limit",
            estimated_cost_usd=Decimal("2"),
            explicit_fallback=True,
        )
    payload = json.loads(path.read_text())
    assert payload["reservations"]
    assert "monthly_spent_usd" in payload


def test_duplicate_settle_does_not_double_count(tmp_path) -> None:
    path = tmp_path / "openrouter-budget-ledger.json"
    guard = OpenRouterBudgetGuard(_limits(), ledger_path=path)
    auth = guard.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("2"),
        explicit_fallback=True,
    )
    guard.record_spend(auth)
    guard.record_spend(auth)
    reloaded = OpenRouterBudgetGuard(_limits(), ledger_path=path)
    assert reloaded.ledger.spent_for_run("run-1") == Decimal("2")
    assert reloaded.ledger.monthly_spent_usd == Decimal("2")
    assert reloaded.ledger.reservations == {}


def test_settle_cost_mismatch_does_not_debit(tmp_path) -> None:
    from openrouter_budget import FallbackAuthorization

    path = tmp_path / "openrouter-budget-ledger.json"
    guard = OpenRouterBudgetGuard(_limits(), ledger_path=path)
    auth = guard.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("2"),
        explicit_fallback=True,
    )
    mismatched = FallbackAuthorization(
        run_id=auth.run_id,
        reason=auth.reason,
        estimated_cost_usd=Decimal("3"),
        remaining_run_budget_usd=auth.remaining_run_budget_usd,
        remaining_monthly_budget_usd=auth.remaining_monthly_budget_usd,
        reservation_id=auth.reservation_id,
    )
    with pytest.raises(ValueError, match="reservation"):
        guard.record_spend(mismatched)
    reloaded = OpenRouterBudgetGuard(_limits(), ledger_path=path)
    assert reloaded.ledger.spent_for_run("run-1") == Decimal("0")
    assert auth.reservation_id in reloaded.ledger.reservations


def test_ledger_persist_uses_lockfile_and_complete_json(tmp_path) -> None:
    path = tmp_path / "openrouter-budget-ledger.json"
    guard = OpenRouterBudgetGuard(_limits(), ledger_path=path)
    guard.authorize_fallback(
        run_id="run-1",
        reason="provider-limit",
        estimated_cost_usd=Decimal("1"),
        explicit_fallback=True,
    )
    lock_path = path.with_name(path.name + ".lock")
    assert lock_path.is_file()
    payload = json.loads(path.read_text())
    assert isinstance(payload, dict)
    assert payload["reservations"]
    assert payload["run_spent"] == {}
