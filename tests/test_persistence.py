import json

from antibot_sdk.models import CaptchaResult
from antibot_sdk.persistence import persist_json, persist_result


def test_persist_json_replaces_destination_atomically(tmp_path):
    destination = tmp_path / "nested" / "result.json"
    path = persist_json({"run": 1, "ok": True}, destination)

    assert path == destination.resolve()
    assert json.loads(destination.read_text(encoding="utf-8")) == {"run": 1, "ok": True}
    assert list(destination.parent.glob(".*.tmp")) == []


def test_persist_result_records_resolved_artifact_path(tmp_path):
    result = CaptchaResult(provider="tencent", ok=False, errors=["rejected"])
    destination = tmp_path / "result.json"

    assert persist_result(result, destination) == destination.resolve()
    assert result.artifacts["output_json"] == str(destination.resolve())
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["artifacts"]["output_json"] == str(destination.resolve())
