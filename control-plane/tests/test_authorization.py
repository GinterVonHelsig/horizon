from pathlib import Path
import sys

import pytest

CONTROL_PLANE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONTROL_PLANE))

from authorization import (
    ACTIVE_RUN_ID,
    ActionMismatchError,
    ActionShapeError,
    ChallengeAlreadyConsumedError,
    ChallengeExpiredError,
    ChallengeStore,
    CodeMismatchError,
    CodeReplayError,
    ForbiddenTermError,
    InvalidTargetError,
    PathTraversalError,
    PriorRunDeniedError,
    StagingRunDeniedError,
    UnicodeNormalizationError,
    UnsupportedActionError,
    WrongHashError,
    action_digest,
    canonical_action,
    canonical_json,
)


ACTION = {
    "action": "queue_next_prompt",
    "target": "comms-01-control-plane",
    "run_id": ACTIVE_RUN_ID,
    "prompt_id": "prompt-01",
    "dry_run": True,
}


@pytest.fixture
def fake_clock():
    def clock():
        return clock.current

    clock.current = 1_700_000_000
    return clock


@pytest.fixture
def store(tmp_path, fake_clock):
    store = ChallengeStore(
        tmp_path / "authorization.sqlite3",
        lambda operator, code, step: True,
        clock=fake_clock,
        totp_step_seconds=30,
    )
    return store


def test_canonicalization_is_stable_across_insertion_order():
    reordered = {
        "dry_run": True,
        "prompt_id": "prompt-01",
        "run_id": ACTIVE_RUN_ID,
        "target": "comms-01-control-plane",
        "action": "queue_next_prompt",
    }

    assert canonical_action(ACTION) == canonical_action(reordered)
    assert canonical_json(ACTION) == canonical_json(reordered)
    assert action_digest(ACTION) == action_digest(reordered)


def test_action_shape_rejects_missing_dry_run_and_extra_fields(store):
    missing_dry_run = dict(ACTION)
    del missing_dry_run["dry_run"]

    extra_field = dict(ACTION)
    extra_field["extra"] = True

    with pytest.raises(ActionShapeError):
        store.create_challenge(missing_dry_run, "operator-01")

    with pytest.raises(ActionShapeError):
        store.create_challenge(extra_field, "operator-01")


def test_unsupported_action_is_rejected(store):
    unsupported = dict(ACTION)
    unsupported["action"] = "unsupported_action"

    with pytest.raises(UnsupportedActionError):
        store.create_challenge(unsupported, "operator-01")


def test_invalid_target_is_rejected(store):
    invalid_target = dict(ACTION)
    invalid_target["target"] = "comms-02-control-plane"

    with pytest.raises(InvalidTargetError):
        store.create_challenge(invalid_target, "operator-01")


def test_path_traversal_target_is_rejected(store):
    traversing_target = dict(ACTION)
    traversing_target["target"] = "../comms-01-control-plane"

    with pytest.raises(PathTraversalError):
        store.create_challenge(traversing_target, "operator-01")


def test_non_normalized_unicode_target_is_rejected(store):
    unicode_target = dict(ACTION)
    unicode_target["target"] = "comms-01-control-plane\u0301"

    with pytest.raises(UnicodeNormalizationError):
        store.create_challenge(unicode_target, "operator-01")


def test_forbidden_target_is_rejected(store):
    forbidden_target = dict(ACTION)
    forbidden_target["target"] = "disposable-production"

    with pytest.raises(ForbiddenTermError):
        store.create_challenge(forbidden_target, "operator-01")


def test_staging_run_is_rejected(store):
    staging_action = dict(ACTION)
    staging_action["run_id"] = f"staging-{ACTIVE_RUN_ID}"

    with pytest.raises(StagingRunDeniedError):
        store.create_challenge(staging_action, "operator-01")


def test_prior_run_is_rejected(store):
    prior_action = dict(ACTION)
    prior_action["run_id"] = f"prior-{ACTIVE_RUN_ID}"

    with pytest.raises(PriorRunDeniedError):
        store.create_challenge(prior_action, "operator-01")


def test_authorization_returns_an_inert_receipt_and_writes_audit(store):
    prompt = store.create_challenge(ACTION, "operator-01")
    receipt = store.authorize(
        prompt.prompt_id,
        "operator-01",
        "123456",
        prompt.action_digest,
    )

    assert receipt is not None

    events = store.audit_events()
    assert events
    assert any(prompt.prompt_id in repr(event) for event in events)


def test_wrong_valid_format_digest_is_rejected(store):
    prompt = store.create_challenge(ACTION, "operator-01")
    wrong_digest = action_digest({**ACTION, "prompt_id": "prompt-02"})

    assert wrong_digest != prompt.action_digest

    with pytest.raises(WrongHashError):
        store.authorize(
            prompt.prompt_id,
            "operator-01",
            "123456",
            wrong_digest,
        )


def test_challenge_expires_at_sixty_seconds(store, fake_clock):
    prompt = store.create_challenge(ACTION, "operator-01")
    fake_clock.current += 60

    with pytest.raises(ChallengeExpiredError):
        store.authorize(
            prompt.prompt_id,
            "operator-01",
            "123456",
            prompt.action_digest,
        )


def test_duplicate_consumption_is_rejected(store):
    prompt = store.create_challenge(ACTION, "operator-01")
    store.authorize(
        prompt.prompt_id,
        "operator-01",
        "123456",
        prompt.action_digest,
    )

    with pytest.raises(ChallengeAlreadyConsumedError):
        store.authorize(
            prompt.prompt_id,
            "operator-01",
            "123456",
            prompt.action_digest,
        )


def test_code_replay_is_rejected_for_a_second_challenge_at_the_same_clock(
    store,
):
    first_prompt = store.create_challenge(ACTION, "operator-01")
    store.authorize(
        first_prompt.prompt_id,
        "operator-01",
        "123456",
        first_prompt.action_digest,
    )

    second_action = dict(ACTION)
    second_action["prompt_id"] = "prompt-02"
    second_prompt = store.create_challenge(second_action, "operator-01")

    with pytest.raises(CodeReplayError):
        store.authorize(
            second_prompt.prompt_id,
            "operator-01",
            "123456",
            second_prompt.action_digest,
        )


def test_false_code_verifier_is_rejected(tmp_path, fake_clock):
    store = ChallengeStore(
        tmp_path / "authorization.sqlite3",
        lambda operator, code, step: False,
        clock=fake_clock,
        totp_step_seconds=30,
    )
    prompt = store.create_challenge(ACTION, "operator-01")

    with pytest.raises(CodeMismatchError):
        store.authorize(
            prompt.prompt_id,
            "operator-01",
            "123456",
            prompt.action_digest,
        )


def test_queue_next_prompt_rejects_a_mismatched_retry_child_action(store):
    retry_action = dict(ACTION)
    retry_action["action"] = "retry_queueable_child"
    retry_action["prompt_id"] = "prompt-02"
    retry_prompt = store.create_challenge(retry_action, "operator-01")

    with pytest.raises(ActionMismatchError):
        store.queue_next_prompt(
            retry_prompt.prompt_id, "operator-01", "123456", retry_prompt.action_digest
        )
