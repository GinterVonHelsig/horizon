"""Required acceptance and injection manifest identifiers."""

from __future__ import annotations

ACCEPTANCE_IDS: tuple[str, ...] = tuple(f"A{i:02d}" for i in range(1, 13))
INJECTION_IDS: tuple[str, ...] = tuple(f"I{i:02d}" for i in range(1, 11))
REQUIRED_ENTRY_IDS: tuple[str, ...] = ACCEPTANCE_IDS + INJECTION_IDS

DEFAULT_PRODUCER = "comms-01-parent-controller"
