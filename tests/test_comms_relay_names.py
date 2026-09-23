"""Naming changes preserve transport compatibility and delivery identity."""
import json
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_comms_relay_is_not_a_delivery_or_network_gateway():
    names = yaml.safe_load((ROOT / "architecture/comms-relay.yaml").read_text())
    assert names["component"]["technical_id"] == "comms-relay"
    assert names["component"]["integration_status"] == "incomplete"
    assert names["component"]["consumers"] == ["Horizon", "Gateway Delivery", "Local Delivery"]
    assert [x["technical_id"] for x in names["delivery_workflows"]] == ["gateway-delivery", "local-delivery"]
    assert names["network_gateway"] == {"address": "192.168.0.1", "rename": False}
    old = names["compatibility"]
    assert old["deployment_mutations_authorized"] is False
    assert old["retained_submission_service"] == "top-delivery-host-gateway.service"
    assert old["retained_submission_socket"] == "/run/top-delivery-host-gateway/gateway.sock"
    assert old["retained_secondary_submission_command"] == "top-delivery-submit"


def test_maintained_program_uses_comms_relay_without_renaming_delivery_contract():
    fixture = json.loads((ROOT / "controller/tests/fixtures/master-program-v1.json").read_text())
    assert any(n.get("owner_role") == "Comms Relay + auth" for n in fixture["nodes"])
    from subworkflow_handoff import HORIZON_PREREQ_CONTRACT
    assert HORIZON_PREREQ_CONTRACT.provider_key == "gateway-horizon-prerequisite-provider"
    assert HORIZON_PREREQ_CONTRACT.executor_adapter == "gateway-delivery"
