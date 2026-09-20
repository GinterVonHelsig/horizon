"""Explicit OpenRouter metered fallback budget enforcement."""

from __future__ import annotations

import fcntl
import json
import os
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Callable, Final

OPENROUTER_PROVIDER: Final = "openrouter"
LEDGER_FILENAME = "openrouter-budget-ledger.json"


@dataclass(frozen=True)
class BudgetLimits:
    per_run_usd: Decimal
    monthly_usd: Decimal

    def __post_init__(self) -> None:
        if self.per_run_usd <= 0 or self.monthly_usd <= 0:
            raise ValueError("budget limits must be positive")


@dataclass
class BudgetLedger:
    limits: BudgetLimits
    monthly_spent_usd: Decimal = Decimal("0")
    run_spent: dict[str, Decimal] = field(default_factory=dict)
    reservations: dict[str, dict[str, str]] = field(default_factory=dict)

    def spent_for_run(self, run_id: str) -> Decimal:
        return self.run_spent.get(run_id, Decimal("0"))

    def reserved_for_run(self, run_id: str) -> Decimal:
        total = Decimal("0")
        for payload in self.reservations.values():
            if payload.get("run_id") == run_id:
                total += Decimal(str(payload.get("estimated_cost_usd", "0")))
        return total

    def reserved_monthly(self) -> Decimal:
        total = Decimal("0")
        for payload in self.reservations.values():
            total += Decimal(str(payload.get("estimated_cost_usd", "0")))
        return total

    def to_dict(self) -> dict[str, object]:
        return {
            "monthly_spent_usd": str(self.monthly_spent_usd),
            "run_spent": {run_id: str(amount) for run_id, amount in self.run_spent.items()},
            "reservations": self.reservations,
        }

    @classmethod
    def from_dict(cls, limits: BudgetLimits, payload: dict[str, object]) -> BudgetLedger:
        run_spent: dict[str, Decimal] = {}
        raw_runs = payload.get("run_spent", {})
        if isinstance(raw_runs, dict):
            for run_id, amount in raw_runs.items():
                run_spent[str(run_id)] = Decimal(str(amount))
        monthly = payload.get("monthly_spent_usd", "0")
        reservations: dict[str, dict[str, str]] = {}
        raw_reservations = payload.get("reservations", {})
        if isinstance(raw_reservations, dict):
            for key, value in raw_reservations.items():
                if isinstance(value, dict):
                    reservations[str(key)] = {
                        "run_id": str(value.get("run_id") or ""),
                        "estimated_cost_usd": str(value.get("estimated_cost_usd") or "0"),
                    }
        return cls(
            limits=limits,
            monthly_spent_usd=Decimal(str(monthly)),
            run_spent=run_spent,
            reservations=reservations,
        )


@dataclass(frozen=True)
class FallbackAuthorization:
    run_id: str
    reason: str
    estimated_cost_usd: Decimal
    remaining_run_budget_usd: Decimal
    remaining_monthly_budget_usd: Decimal
    reservation_id: str = ""


class BudgetExceededError(ValueError):
    pass


class SilentFallbackError(ValueError):
    pass


class OpenRouterBudgetGuard:
    """Never silently fall back to OpenRouter; require explicit budget approval.

    Cross-process exclusion requires a shared ``ledger_path``. In-memory
    construction (no path) can still reject silent fallback, but cannot
    authorize or settle. Lock scope is a sibling ``<ledger>.lock`` file held
    exclusive for the read-mutate-atomic-replace window. Persistence writes a
    complete JSON tempfile, fsyncs it, then ``os.replace`` onto the ledger.
    Stale reservations stay fail-closed; a later envelope owns TTL/reconcile.
    """

    def __init__(
        self,
        limits: BudgetLimits,
        ledger: BudgetLedger | None = None,
        *,
        ledger_path: Path | None = None,
    ) -> None:
        self._limits = limits
        self._ledger_path = Path(ledger_path).resolve() if ledger_path is not None else None
        if ledger is not None:
            self._ledger = ledger
        elif self._ledger_path is not None and self._ledger_path.is_file():
            payload = json.loads(self._ledger_path.read_text())
            if not isinstance(payload, dict):
                raise ValueError("OpenRouter budget ledger must be a JSON object")
            self._ledger = BudgetLedger.from_dict(limits, payload)
        else:
            self._ledger = BudgetLedger(limits=limits)

    @property
    def ledger(self) -> BudgetLedger:
        return self._ledger

    def _require_ledger_path(self) -> Path:
        if self._ledger_path is None:
            raise ValueError("ledger_path is required for OpenRouter budget authorize/settle")
        return self._ledger_path

    def authorize_fallback(
        self,
        *,
        run_id: str,
        reason: str,
        estimated_cost_usd: Decimal,
        explicit_fallback: bool,
    ) -> FallbackAuthorization:
        if not run_id:
            raise ValueError("run_id is required")
        if not reason:
            raise ValueError("fallback reason is required")
        if estimated_cost_usd <= 0:
            raise ValueError("estimated_cost_usd must be positive")
        if not explicit_fallback:
            raise SilentFallbackError("OpenRouter fallback requires explicit budget approval")
        self._require_ledger_path()

        authorization: dict[str, FallbackAuthorization] = {}

        def mutate(ledger: BudgetLedger) -> None:
            remaining_run = self._limits.per_run_usd - ledger.spent_for_run(run_id) - ledger.reserved_for_run(run_id)
            remaining_monthly = self._limits.monthly_usd - ledger.monthly_spent_usd - ledger.reserved_monthly()
            if estimated_cost_usd > remaining_run:
                raise BudgetExceededError("per-run OpenRouter budget exceeded")
            if estimated_cost_usd > remaining_monthly:
                raise BudgetExceededError("monthly OpenRouter budget exceeded")
            reservation_id = uuid.uuid4().hex
            ledger.reservations[reservation_id] = {
                "run_id": run_id,
                "estimated_cost_usd": str(estimated_cost_usd),
            }
            authorization["value"] = FallbackAuthorization(
                run_id=run_id,
                reason=reason,
                estimated_cost_usd=estimated_cost_usd,
                remaining_run_budget_usd=remaining_run - estimated_cost_usd,
                remaining_monthly_budget_usd=remaining_monthly - estimated_cost_usd,
                reservation_id=reservation_id,
            )

        self._with_ledger(mutate)
        return authorization["value"]

    def record_spend(self, authorization: FallbackAuthorization) -> None:
        self._require_ledger_path()

        def mutate(ledger: BudgetLedger) -> None:
            reservation_id = authorization.reservation_id
            if not reservation_id:
                return
            if reservation_id not in ledger.reservations:
                return
            reserved = Decimal(str(ledger.reservations[reservation_id]["estimated_cost_usd"]))
            if reserved != authorization.estimated_cost_usd:
                raise ValueError("reservation cost mismatch")
            del ledger.reservations[reservation_id]
            ledger.run_spent[authorization.run_id] = (
                ledger.spent_for_run(authorization.run_id) + authorization.estimated_cost_usd
            )
            ledger.monthly_spent_usd += authorization.estimated_cost_usd

        self._with_ledger(mutate)

    def _with_ledger(self, mutator: Callable[[BudgetLedger], None]) -> None:
        path = self._require_ledger_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_name(path.name + ".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        tmp: Path | None = None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            if path.is_file():
                raw = path.read_text()
                payload = json.loads(raw) if raw.strip() else {}
            else:
                payload = {}
            if payload and not isinstance(payload, dict):
                raise ValueError("OpenRouter budget ledger must be a JSON object")
            self._ledger = BudgetLedger.from_dict(
                self._limits, payload if isinstance(payload, dict) else {}
            )
            mutator(self._ledger)
            tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex}")
            tmp.write_text(json.dumps(self._ledger.to_dict(), indent=2, sort_keys=True) + "\n")
            with tmp.open("r+") as handle:
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            tmp = None
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if tmp is not None and tmp.exists():
                tmp.unlink()
            os.close(fd)

    def _persist_ledger(self) -> None:
        if self._ledger_path is None:
            return
        self._with_ledger(lambda _ledger: None)
