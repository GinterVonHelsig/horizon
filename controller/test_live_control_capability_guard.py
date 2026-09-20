from __future__ import annotations

from types import SimpleNamespace

import attestation
import comms01_scope as scope


class Cursor:
    def __init__(self, database_name: str, database_role: str) -> None:
        self.database_name = database_name
        self.database_role = database_role

    def __enter__(self) -> "Cursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _query: str) -> None:
        return None

    def fetchone(self) -> tuple[str, str, str, int]:
        return (self.database_name, self.database_role, "127.0.0.1", 5432)


class Connection:
    def __init__(self, database_name: str, database_role: str) -> None:
        self.database_name = database_name
        self.database_role = database_role

    def cursor(self) -> Cursor:
        return Cursor(self.database_name, self.database_role)


def identity(database_name: str) -> SimpleNamespace:
    return SimpleNamespace(
        database_endpoint="local",
        database_port=5432,
        database_name=database_name,
        workflow_database_role="top_delivery_workflow",
        authority_database_role="top_delivery_authority",
        controller_service="top-delivery-controller",
    )


def prepare(monkeypatch, database_name: str, disposable: bool) -> None:
    monkeypatch.setattr(scope, "_attestation_identity", lambda: identity(database_name))
    monkeypatch.setattr(attestation, "assert_endpoint_binding", lambda *_args: None)
    monkeypatch.setattr(scope, "assert_service_name", lambda *_args: None)
    monkeypatch.setattr(scope, "is_disposable_test_database", lambda _url: disposable)


def test_live_control_database_does_not_load_disposable_capability(monkeypatch) -> None:
    prepare(monkeypatch, "top_delivery_control_p1", False)

    def fail_if_loaded():
        raise AssertionError("live control path loaded disposable capability")

    monkeypatch.setattr(scope, "load_signed_disposable_capability", fail_if_loaded)
    database_url = "postgresql://top_delivery_workflow@127.0.0.1:5432/top_delivery_control_p1"
    assert scope.verify_connection_identity(
        database_url=database_url,
        connection=Connection("top_delivery_control_p1", "top_delivery_workflow"),
        expected_role="top_delivery_workflow",
        expected_service="top-delivery-controller",
    ) == ("top_delivery_control_p1", "top_delivery_workflow")


def test_disposable_database_still_requires_capability(monkeypatch) -> None:
    prepare(monkeypatch, "td_test_guard", True)
    capability = SimpleNamespace(database_role="top_delivery_workflow", operation="create_database")
    load_count = 0

    def load_capability():
        nonlocal load_count
        load_count += 1
        return capability

    monkeypatch.setattr(scope, "load_signed_disposable_capability", load_capability)
    database_url = "postgresql://top_delivery_workflow@127.0.0.1:5432/td_test_guard"
    assert scope.verify_connection_identity(
        database_url=database_url,
        connection=Connection("td_test_guard", "top_delivery_workflow"),
        expected_role="top_delivery_workflow",
        expected_service="top-delivery-controller",
    ) == ("td_test_guard", "top_delivery_workflow")
    assert load_count == 1
