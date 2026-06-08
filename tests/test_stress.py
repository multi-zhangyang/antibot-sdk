import asyncio

from antibot_sdk.models import BrowserResult
from antibot_sdk.stress import run_stress


def test_run_stress_summarizes_success_and_failure(tmp_path):
    async def once(i: int):
        if i == 2:
            raise RuntimeError("boom")
        return BrowserResult(ok=True, state="clear", url=f"https://example.com/{i}")

    out = tmp_path / "stress.json"
    ret = asyncio.run(
        run_stress(
            name="unit",
            runs=3,
            concurrency=2,
            per_run_timeout=5,
            output_json=str(out),
            run_once=once,
        )
    )
    assert ret["summary"]["ok"] == 2
    assert ret["summary"]["fail"] == 1
    assert out.is_file()
