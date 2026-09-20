import json
import sys
import tempfile
import unittest
from pathlib import Path


CONTROL_PLANE = Path(__file__).resolve().parents[1]
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from signal_bridge import (  # noqa: E402
    HermesCommandDisabledError,
    HermesCommandGuard,
    SignalBridge,
    SignalEnvelope,
    SignalEnvelopeError,
    SignalIdentityPolicy,
    hermes_typed_command,
    parse_signal_envelope_reply,
)


class FakeController:
    def __init__(self, output='{"controller":"exact"}\r\n'):
        self.output = output
        self.calls = []

    def handle_text(self, text, sender, is_group=False):
        self.calls.append((text, sender, is_group))
        return self.output


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class SignalBridgeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.directory.name) / "signal.sqlite3"
        self.policy = SignalIdentityPolicy(
            approved_sender_id="approved-sender",
            pinned_identity_fingerprint="pinned-fingerprint",
        )

    def tearDown(self):
        self.directory.cleanup()

    def envelope(self, message_id="message-1", **changes):
        values = {
            "message_id": message_id,
            "sender_id": "approved-sender",
            "identity_fingerprint": "pinned-fingerprint",
            "text": "/status",
            "is_group": False,
        }
        values.update(changes)
        return SignalEnvelope(**values)

    def bridge(self, controller, **kwargs):
        return SignalBridge(
            controller,
            self.policy,
            self.db_path,
            **kwargs,
        )

    def test_direct_reply_is_returned_byte_for_byte(self):
        output = '{"z": [1, 2], "newline": "kept"}\r\n'
        controller = FakeController(output)
        bridge = self.bridge(controller)
        try:
            self.assertEqual(bridge.handle(self.envelope()), output)
            self.assertEqual(controller.calls, [("/status", "approved-sender", False)])
        finally:
            bridge.close()

    def test_unknown_group_and_identity_change_never_call_controller(self):
        controller = FakeController()
        bridge = self.bridge(controller)
        try:
            unknown = bridge.handle(
                self.envelope("unknown", sender_id="other-sender")
            )
            group = bridge.handle(self.envelope("group", is_group=True))
            changed = bridge.handle(
                self.envelope(
                    "changed", identity_fingerprint="different-fingerprint"
                )
            )
            self.assertEqual(controller.calls, [])
            self.assertEqual(json.loads(unknown), {"error": "sender_unknown"})
            self.assertEqual(json.loads(group), {"error": "group_not_allowed"})
            self.assertEqual(
                json.loads(changed), {"error": "identity_key_changed"}
            )
            events = bridge.audit_events()
            self.assertIn("identity_key_change", [e["event_type"] for e in events])
        finally:
            bridge.close()

    def test_duplicate_replays_exact_output_after_restart(self):
        output = '{"controller":"not reformatted"}\n'
        first_controller = FakeController(output)
        first = self.bridge(first_controller)
        self.assertEqual(first.handle(self.envelope("durable")), output)
        first.close()

        second_controller = FakeController('{"should":"not be used"}')
        second = self.bridge(second_controller)
        try:
            self.assertEqual(second.handle(self.envelope("durable")), output)
            self.assertEqual(second_controller.calls, [])
            self.assertIn(
                "duplicate_message",
                [event["event_type"] for event in second.audit_events()],
            )
        finally:
            second.close()

    def test_rate_limit_is_bounded_and_in_memory(self):
        clock = FakeClock()
        controller = FakeController()
        bridge = self.bridge(
            controller,
            max_messages=1,
            window_seconds=10,
            max_rate_entries=1,
            clock=clock,
        )
        try:
            self.assertEqual(
                bridge.handle(self.envelope("first")),
                controller.output,
            )
            self.assertEqual(
                json.loads(bridge.handle(self.envelope("second"))),
                {"error": "rate_limited"},
            )
            self.assertLessEqual(bridge._rate_limiter.key_count, 1)
            clock.value = 11
            self.assertEqual(
                bridge.handle(self.envelope("third")),
                controller.output,
            )
            self.assertEqual(len(controller.calls), 2)
        finally:
            bridge.close()

    def test_closed_parser_rejects_malformed_identity_and_unstable_values(self):
        base = self.envelope().as_mapping()
        with self.assertRaises(SignalEnvelopeError):
            SignalEnvelope.from_mapping({key: value for key, value in base.items()
                                         if key != "sender_id"})
        with self.assertRaises(SignalEnvelopeError):
            SignalEnvelope.from_mapping(dict(base, unexpected="value"))
        with self.assertRaises(SignalEnvelopeError):
            SignalEnvelope.from_mapping(
                dict(base, identity_fingerprint="fingerprint-\N{LATIN SMALL LETTER E WITH ACUTE}")
            )
        with self.assertRaises(SignalEnvelopeError):
            SignalEnvelope.from_mapping(dict(base, text="e\u0301"))
        self.assertEqual(
            parse_signal_envelope_reply(dict(base, unexpected="value")),
            '{"error":"malformed_envelope"}',
        )

    def test_hermes_typed_command_path_is_disabled(self):
        guard = HermesCommandGuard()
        for operation in (
            guard.author,
            guard.transform,
            guard.author_typed_reply,
            guard.transform_typed_reply,
        ):
            with self.assertRaises(HermesCommandDisabledError):
                operation("/status")
        with self.assertRaises(HermesCommandDisabledError):
            hermes_typed_command("/status")


if __name__ == "__main__":
    unittest.main()
