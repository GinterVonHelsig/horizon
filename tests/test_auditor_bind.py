"""Unit tests for bound_auditor_verdict stream requirements."""

from __future__ import annotations

import hashlib

from auditor_bind import bound_auditor_verdict

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
STDOUT_SHA256 = "a" * 64
NONEMPTY_STDERR_SHA256 = "b" * 64
CRITERION = "PASS_HORIZON_FINISH_PATH"


def _payload(refs: list[dict[str, str]], *, verdict: str = "approve", met: bool = True) -> dict:
    return {
        "verdict": verdict,
        "criteria": [
            {
                "criterion": CRITERION,
                "met": met,
                "rationale": "fixture",
                "evidence_refs": refs,
            }
        ],
    }


def test_empty_stderr_is_not_required_when_stdout_is_cited() -> None:
    evidence = [
        {"stream": "stdout", "artifact_path": "stdout.txt", "sha256": STDOUT_SHA256},
        {"stream": "stderr", "artifact_path": "stderr.txt", "sha256": EMPTY_SHA256},
    ]
    payload = _payload([{"name": "stdout", "sha256": STDOUT_SHA256}])
    assert (
        bound_auditor_verdict(
            payload,
            acceptance=[CRITERION],
            trusted={"substring_ok": True},
            executor_evidence=evidence,
        )
        == "approve"
    )


def test_nonempty_stderr_missing_from_refs_rejects_approve() -> None:
    evidence = [
        {"stream": "stdout", "artifact_path": "stdout.txt", "sha256": STDOUT_SHA256},
        {"stream": "stderr", "artifact_path": "stderr.txt", "sha256": NONEMPTY_STDERR_SHA256},
    ]
    payload = _payload([{"name": "stdout", "sha256": STDOUT_SHA256}])
    assert (
        bound_auditor_verdict(
            payload,
            acceptance=[CRITERION],
            trusted={"substring_ok": True},
            executor_evidence=evidence,
        )
        == "reject"
    )


def test_empty_stdout_is_still_required() -> None:
    evidence = [
        {"stream": "stdout", "artifact_path": "stdout.txt", "sha256": EMPTY_SHA256},
        {"stream": "stderr", "artifact_path": "stderr.txt", "sha256": NONEMPTY_STDERR_SHA256},
    ]
    payload = _payload([{"name": "stderr", "sha256": NONEMPTY_STDERR_SHA256}])
    assert (
        bound_auditor_verdict(
            payload,
            acceptance=[CRITERION],
            trusted={"substring_ok": True},
            executor_evidence=evidence,
        )
        == "reject"
    )
