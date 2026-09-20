from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from signal_adapter import (
    AUTHORIZATION_MODE,
    READ_ONLY_MODE,
    ActionQueue,
    AuthServiceError,
    ControllerSocketClient,
    RpcError,
    SignalAdapter,
    _compact_fingerprint,
    format_signal_outbound,
)
from authorization import CHALLENGE_TTL_SECONDS, action_digest


class FakeRPC:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, method: str, params: dict[str, object], **_kwargs: object) -> object:
        self.calls.append((method, params))
        if method == "listIdentities":
            return [
                {
                    "number": "+15550000001",
                    "fingerprint": "AA BB",
                    "trustLevel": "TRUSTED_VERIFIED",
                }
            ]
        if method == "POST /v1/challenges":
            return {"challenge_id": "challenge-1", "expires_at": "later"}
        if method == "POST /v1/challenges/challenge-1/authorize":
            if params.get("code") != "123456":
                raise AuthServiceError("authorization_rejected")
            return {
                "authorized": True,
                "action_hash": hashlib.sha256(params["action_hash"].encode()).hexdigest(),
            }
        if method == "receive":
            return []
        return {"results": [{"type": "SUCCESS"}]}


class FakeController:
    calls: list[str] = []

    def handle_text(self, text: str, sender_id: str, *, is_group: bool = False) -> str:
        FakeController.calls.append(text)
        assert sender_id == "+15550000001"
        assert is_group is False
        if text == "active-runs":
            return json.dumps(
                {
                    "runs": [
                        {
                            "run_id": "20260810T050500Z-comms01-repair",
                            "phase": "4.5",
                            "status": "active",
                            "blockers": [],
                            "next_action": "queue-next-prompt",
                        }
                    ]
                },
                separators=(",", ":"),
            )
        return json.dumps({"command": text}, separators=(",", ":"))


class SignalAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeController.calls = []
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "signal.sqlite3"
        self.rpc = FakeRPC()
        self.adapter = SignalAdapter(
            rpc=self.rpc,  # type: ignore[arg-type]
            auth_rpc=self.rpc,  # type: ignore[arg-type]
            controller=ControllerSocketClient("/does/not/exist", "operator-01"),
            state_db=self.db,
            account="+17325889188",
            allowed_sender="+15550000001",
            pinned_fingerprint="AA BB",
            operator_id="operator-01",
        )
        fake_controller = FakeController()
        self.adapter.controller = fake_controller  # type: ignore[assignment]
        self.adapter.bridge._controller = fake_controller

    def tearDown(self) -> None:
        self.adapter.close()
        self.temp.cleanup()

    @staticmethod
    def raw(
        text: str,
        *,
        sender: str = "+15550000001",
        group: bool = False,
        timestamp: int = 99,
    ) -> dict[str, object]:
        data: dict[str, object] = {"timestamp": timestamp, "message": text}
        if group:
            data["groupInfo"] = {"groupId": "g"}
        return {
            "envelope": {
                "sourceNumber": sender,
                "sourceUuid": "uuid-1",
                "sourceDevice": 1,
                "dataMessage": data,
            }
        }

    def test_identity_is_pinned_and_normalized(self) -> None:
        self.assertEqual(_compact_fingerprint("AA BB"), "aabb")
        self.assertEqual(self.adapter.verify_identity(), "TRUSTED_VERIFIED")

    def test_read_only_command_round_trip(self) -> None:
        item = self.adapter.process_envelope(self.raw("/status"))
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(json.loads(item[1]), {"command": "status"})

    def test_commands_returns_one_line_comma_separated_signal_commands(self) -> None:
        item = self.adapter.process_envelope(self.raw("commands", timestamp=98))
        self.assertIsNotNone(item)
        assert item is not None
        payload = json.loads(item[1])
        self.assertEqual(payload["mode"], READ_ONLY_MODE)
        self.assertEqual(
            payload["commands"],
            [
                "status",
                "architecture-summary",
                "recommended",
                "active-runs",
                "latest-evidence",
                "next-step (read-only run next action)",
                "trading-summary [YYYY-MM-DD]",
                "artifact lookup (read-only evidence)",
                "next (2FA queue)",
                "authorize CODE",
                "commands",
            ],
        )
        rendered = format_signal_outbound(item[1])
        self.assertIn(
            "Available commands: status, architecture-summary, recommended, active-runs, "
            "latest-evidence, next-step (read-only run next action), "
            "trading-summary [YYYY-MM-DD], artifact lookup (read-only evidence), "
            "next (2FA queue), authorize CODE, commands",
            rendered,
        )
        self.assertNotIn("\n- ", rendered)
        self.assertEqual(FakeController.calls, [])

    def test_architecture_and_trading_summary_formatters_are_human_readable(self) -> None:
        architecture = format_signal_outbound(
            json.dumps(
                {
                    "mode": READ_ONLY_MODE,
                    "architecture_summary": {
                        "title": "Trading Platform Advancement",
                        "as_of": "2026-08-10",
                        "current_reality": ["Service active"],
                        "tree": [
                            {
                                "id": "0",
                                "name": "Workflow",
                                "status": "ACTIVE",
                                "items": [{"name": "Controller", "status": "DONE"}],
                            }
                        ],
                    },
                    "architecture_path": "architecture/project-status.json",
                },
                separators=(",", ":"),
            )
        )
        self.assertIn("Master project:", architecture)
        self.assertIn("0. Workflow [ACTIVE]", architecture)
        self.assertIn("Controller [DONE]", architecture)
        self.assertNotIn("model-routing.yaml", architecture)
        summary = format_signal_outbound(
            json.dumps(
                {
                    "mode": READ_ONLY_MODE,
                    "trading_summary": {
                        "date": "2026-08-10",
                        "financial": {
                            "trusted_closed_pnl": 0,
                            "wins": 0,
                            "losses": 0,
                        },
                        "operational": {"service_ok": True},
                        "verdict": "flat",
                    },
                    "summary_path": "reports/trading-summary-2026-08-10.json",
                },
                separators=(",", ":"),
            )
        )
        self.assertIn("Trading summary: 2026-08-10", summary)
        self.assertIn("Trusted closed P&L: $0.00", summary)
        self.assertIn("Verdict: flat", summary)

    def test_unknown_sender_and_group_are_rejected_without_controller_call(self) -> None:
        self.assertIsNone(self.adapter.process_envelope(self.raw("status", sender="+15550000002")))
        self.assertIsNone(self.adapter.process_envelope(self.raw("status", group=True)))

    def test_receive_uses_daemon_account_and_no_second_account_parameter(self) -> None:
        self.adapter.receive_once(timeout=1, max_messages=2)
        receive_calls = [call for call in self.rpc.calls if call[0] == "receive"]
        self.assertEqual(len(receive_calls), 1)
        self.assertEqual(receive_calls[0][1], {"timeout": 1, "maxMessages": 2})

    def test_malformed_receive_result_is_not_treated_as_empty_success(self) -> None:
        original = self.rpc.call

        def malformed(method: str, params: dict[str, object], **kwargs: object) -> object:
            if method == "receive":
                return {"unexpected": True}
            return original(method, params, **kwargs)

        self.rpc.call = malformed  # type: ignore[method-assign]
        with self.assertRaises(RpcError):
            self.adapter.receive_once()

    def test_challenge_and_authorized_intent_are_durable_and_idempotent(self) -> None:
        challenge = self.adapter.process_envelope(self.raw("next"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        challenge_json = json.loads(challenge[1])
        self.assertEqual(challenge_json["challenge_id"], "challenge-1")
        authorized = self.adapter.process_envelope(self.raw("authorize 123456", timestamp=100))
        self.assertIsNotNone(authorized)
        assert authorized is not None
        self.assertEqual(json.loads(authorized[1])["state"], "pending-parent")
        self.assertEqual(
            json.loads(authorized[1])["action_details"]["run_id"],
            "20260810T050500Z-comms01-repair",
        )
        duplicate = self.adapter.state._connection.execute(
            "SELECT count(*) FROM authorized_actions"
        ).fetchone()[0]
        self.assertEqual(duplicate, 1)

    def test_successful_next_authorization_opens_seven_day_session(self) -> None:
        challenge = self.adapter.process_envelope(self.raw("next", timestamp=300))
        self.assertIsNotNone(challenge)
        authorized = self.adapter.process_envelope(
            self.raw("authorize 123456", timestamp=301)
        )
        self.assertIsNotNone(authorized)
        follow_up = self.adapter.process_envelope(self.raw("next", timestamp=302))
        self.assertIsNotNone(follow_up)
        assert follow_up is not None
        payload = json.loads(follow_up[1])
        self.assertEqual(payload["state"], "pending-parent")
        self.assertEqual(payload["authorization_method"], "seven-day-session")
        self.assertGreater(payload["session_expires_at"], self.adapter.now())

    def test_bare_code_without_pending_challenge(self) -> None:
        item = self.adapter.process_envelope(self.raw("654321"))
        self.assertIsNotNone(item)
        assert item is not None
        payload = json.loads(item[1])
        self.assertEqual(payload["error"], "bare_code_rejected")
        self.assertEqual(payload["mode"], AUTHORIZATION_MODE)
        self.assertEqual(payload["next_action"], "next")
        self.assertIn("next", payload["message"])
        self.assertNotIn("654321", item[1])
        self.assertEqual(FakeController.calls, [])

    def test_bare_code_with_pending_challenge_explains_authorize_command(self) -> None:
        challenge = self.adapter.process_envelope(self.raw("queue-next-prompt"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        item = self.adapter.process_envelope(self.raw("654321", timestamp=101))
        self.assertIsNotNone(item)
        assert item is not None
        payload = json.loads(item[1])
        self.assertEqual(payload["error"], "bare_code_rejected")
        self.assertEqual(payload["mode"], AUTHORIZATION_MODE)
        self.assertEqual(payload["next_action"], "authorize CODE")
        self.assertIn("authorize CODE", payload["message"])
        self.assertNotIn("654321", item[1])

    def test_invalid_authorize_code_is_rejected_before_queueing(self) -> None:
        challenge = self.adapter.process_envelope(self.raw("queue-next-prompt"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        rejected = self.adapter.process_envelope(self.raw("authorize 000000", timestamp=102))
        self.assertIsNotNone(rejected)
        assert rejected is not None
        payload = json.loads(rejected[1])
        self.assertEqual(payload["error"], "authorization_rejected")
        self.assertEqual(payload["mode"], AUTHORIZATION_MODE)
        count = self.adapter.state._connection.execute(
            "SELECT count(*) FROM authorized_actions"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_bare_code_ignores_expired_challenge(self) -> None:
        challenge = self.adapter.process_envelope(self.raw("queue-next-prompt"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        challenge_json = json.loads(challenge[1])
        stale_at = self.adapter.now() - CHALLENGE_TTL_SECONDS - 1
        self.adapter.state._connection.execute(
            "UPDATE pending_challenges SET created_at=? WHERE challenge_id=?",
            (stale_at, challenge_json["challenge_id"]),
        )
        item = self.adapter.process_envelope(self.raw("654321", timestamp=103))
        self.assertIsNotNone(item)
        assert item is not None
        payload = json.loads(item[1])
        self.assertEqual(payload["error"], "bare_code_rejected")
        self.assertEqual(payload["mode"], AUTHORIZATION_MODE)
        self.assertEqual(payload["next_action"], "next")
        self.assertIn("expired", payload["message"].lower())
        self.assertNotIn("reply", payload)
        self.assertNotIn("654321", item[1])

    def test_execution_rate_limited_includes_authorization_mode(self) -> None:
        for index in range(5):
            self.adapter.process_envelope(
                self.raw("queue-next-prompt", timestamp=200 + index)
            )
        item = self.adapter.process_envelope(self.raw("queue-next-prompt", timestamp=205))
        self.assertIsNotNone(item)
        assert item is not None
        payload = json.loads(item[1])
        self.assertEqual(payload["error"], "rate_limited")
        self.assertEqual(payload["mode"], AUTHORIZATION_MODE)
        self.assertIn("message", payload)
        self.assertIn("next_action", payload)

    def test_malformed_queue_next_prompt_includes_authorization_mode(self) -> None:
        item = self.adapter.process_envelope(self.raw("queue-next-prompt extra"))
        self.assertIsNotNone(item)
        assert item is not None
        payload = json.loads(item[1])
        self.assertEqual(payload["error"], "command_syntax")
        self.assertEqual(payload["mode"], AUTHORIZATION_MODE)
        self.assertIn("next", payload["message"])
        self.assertEqual(payload["next_action"], "next")

    def test_flush_formats_read_only_status_for_signal(self) -> None:
        sent: list[str] = []

        def capture(message: str) -> bool:
            sent.append(message)
            return True

        self.adapter._send = capture  # type: ignore[method-assign]
        response = json.dumps(
            {
                "mode": READ_ONLY_MODE,
                "run_id": "20260810T004319Z-b626467e",
                "phase": "3A",
                "status": "active",
                "evidence_paths": ["evidence/result.json"],
                "blockers": [],
                "next_action": "review evidence",
                "evidence": [
                    {
                        "path": "evidence/result.json",
                        "sha256": "abc123",
                        "size": 12,
                    }
                ],
            },
            separators=(",", ":"),
        )
        self.assertTrue(self.adapter.flush(("msg-1", response)))
        self.assertEqual(len(sent), 1)
        self.assertIn("TOP-DELIVERY", sent[0])
        self.assertIn("Mode: read-only", sent[0])
        self.assertIn("Run: B626467e", sent[0])
        self.assertIn("Phase: 3A", sent[0])
        self.assertIn("Status: active", sent[0])
        self.assertIn("Blockers: none", sent[0])
        self.assertIn("Next: review evidence", sent[0])
        self.assertIn("Evidence: 1 file(s)", sent[0])
        self.assertNotIn("{", sent[0])

    def test_flush_maps_legacy_queue_action_to_next(self) -> None:
        rendered = format_signal_outbound(
            json.dumps(
                {
                    "mode": READ_ONLY_MODE,
                    "run_id": "run-1",
                    "phase": "control-plane-remediation",
                    "status": "completed",
                    "blockers": [],
                    "next_action": "queue-next-prompt",
                },
                separators=(",", ":"),
            )
        )
        self.assertIn("Next: next", rendered)
        self.assertNotIn("Next: queue-next-prompt", rendered)

    def test_process_envelope_keeps_json_while_flush_formats_signal(self) -> None:
        sent: list[str] = []

        def capture(message: str) -> bool:
            sent.append(message)
            return True

        self.adapter._send = capture  # type: ignore[method-assign]
        status_json = json.dumps(
            {
                "mode": READ_ONLY_MODE,
                "run_id": "run-1",
                "phase": "control-plane-remediation",
                "status": "active",
                "blockers": [],
                "next_action": "send status",
            },
            separators=(",", ":"),
        )
        self.adapter.bridge._controller = type(
            "StatusController",
            (),
            {
                "handle_text": staticmethod(
                    lambda text, sender_id, is_group=False: status_json
                )
            },
        )()
        item = self.adapter.process_envelope(self.raw("status"))
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item[1], status_json)
        cached = self.adapter._cached_response(item[0])
        self.assertEqual(cached, status_json)
        self.adapter.flush(item)
        self.assertIn("Mode: read-only", sent[0])
        self.assertNotIn("{", sent[0])

    def test_flush_formats_queue_challenge_for_signal(self) -> None:
        sent: list[str] = []

        def capture(message: str) -> bool:
            sent.append(message)
            return True

        self.adapter._send = capture  # type: ignore[method-assign]
        challenge = self.adapter.process_envelope(self.raw("queue-next-prompt"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        challenge_json = json.loads(challenge[1])
        self.assertEqual(challenge_json["run_id"], "20260810T050500Z-comms01-repair")
        self.adapter.flush(challenge)
        self.assertIn("2FA authorization request", sent[0])
        self.assertIn("Action: Queue the next approved TOP-DELIVERY prompt", sent[0])
        self.assertIn("Run: Comms-01 Repair", sent[0])
        self.assertIn("Phase: 4.5", sent[0])
        self.assertIn("Reply exactly: authorize CODE", sent[0])
        self.assertNotIn("Reply exactly:\n", sent[0])
        self.assertNotIn("Replace CODE", sent[0])
        self.assertNotIn("{", sent[0])

    def test_authorization_template_does_not_strip_placeholders(self) -> None:
        rendered = format_signal_outbound(
            json.dumps(
                {
                    "mode": AUTHORIZATION_MODE,
                    "action": "queue_next_prompt",
                    "challenge_id": "challenge-1",
                    "action_digest": "a" * 64,
                    "expires_at": "2026-08-10T18:32:31+00:00",
                    "reply": "authorize challenge-1 " + "a" * 64 + " <6-digit-code>",
                },
                separators=(",", ":"),
            )
        )
        self.assertIn("Reply exactly: authorize CODE", rendered)
        self.assertNotIn("Reply exactly:\n", rendered)
        self.assertNotIn("a" * 64, rendered)
        self.assertNotIn("<6-digit-code>", rendered)

    def test_flush_formats_authorization_error_for_signal(self) -> None:
        sent: list[str] = []

        def capture(message: str) -> bool:
            sent.append(message)
            return True

        self.adapter._send = capture  # type: ignore[method-assign]
        challenge = self.adapter.process_envelope(self.raw("queue-next-prompt"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        rejected = self.adapter.process_envelope(self.raw("authorize 000000", timestamp=102))
        self.assertIsNotNone(rejected)
        assert rejected is not None
        self.assertIn('"error":"authorization_rejected"', rejected[1])
        self.adapter.flush(rejected)
        self.assertIn("Mode: authorization", sent[0])
        self.assertIn("Error:", sent[0])
        self.assertIn("Next: next", sent[0])
        self.assertNotIn("{", sent[0])

    def test_authorization_syntax_error_keeps_actionable_template(self) -> None:
        sent: list[str] = []

        def capture(message: str) -> bool:
            sent.append(message)
            return True

        self.adapter._send = capture  # type: ignore[method-assign]
        challenge = self.adapter.process_envelope(self.raw("queue-next-prompt"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        malformed = self.adapter.process_envelope(
            self.raw("authorize challenge-1 digest", timestamp=104)
        )
        self.assertIsNotNone(malformed)
        assert malformed is not None
        self.adapter.flush(malformed)
        self.assertIn("Use exactly: authorize CODE", sent[0])
        self.assertIn("Next: next", sent[0])
        self.assertNotIn("<challenge-id>", sent[0])

    def test_flush_formats_pending_parent_success_for_signal(self) -> None:
        sent: list[str] = []

        def capture(message: str) -> bool:
            sent.append(message)
            return True

        self.adapter._send = capture  # type: ignore[method-assign]
        challenge = self.adapter.process_envelope(self.raw("queue-next-prompt"))
        self.assertIsNotNone(challenge)
        assert challenge is not None
        authorized = self.adapter.process_envelope(self.raw("authorize 123456", timestamp=103))
        self.assertIsNotNone(authorized)
        assert authorized is not None
        self.assertIn('"state":"pending-parent"', authorized[1])
        self.adapter.flush(authorized)
        self.assertIn("2FA authorization accepted", sent[0])
        self.assertIn("Action: Queue the next approved TOP-DELIVERY prompt", sent[0])
        self.assertIn("Run: Comms-01 Repair", sent[0])
        self.assertIn("Execution: not started; no prompt has run.", sent[0])
        self.assertIn("Next: status", sent[0])
        self.assertNotIn("{", sent[0])

    def test_flush_uses_safe_fallback_for_malformed_and_html(self) -> None:
        sent: list[str] = []

        def capture(message: str) -> bool:
            sent.append(message)
            return True

        self.adapter._send = capture  # type: ignore[method-assign]
        self.adapter.flush(("msg-bad", "not-json"))
        self.assertIn("not valid JSON", sent[0])
        self.assertNotIn("{", sent[0])
        self.adapter.flush(
            ("msg-html", '<html><script>alert(1)</script><body>status</body></html>')
        )
        self.assertIn("not valid JSON", sent[1])
        self.assertNotIn("<script", sent[1].lower())
        self.assertNotIn("alert", sent[1])

    def test_format_signal_outbound_active_runs(self) -> None:
        rendered = format_signal_outbound(
            json.dumps(
                {
                    "mode": READ_ONLY_MODE,
                    "status": "active",
                    "blockers": [],
                    "next_action": "inspect one of the active runs",
                    "runs": [
                        {
                            "run_id": "run-a",
                            "phase": "3A",
                            "status": "active",
                            "blockers": [],
                            "next_action": "continue",
                        }
                    ],
                },
                separators=(",", ":"),
            )
        )
        self.assertIn("Active runs: 1", rendered)
        self.assertIn("Run A", rendered)


if __name__ == "__main__":
    unittest.main()
