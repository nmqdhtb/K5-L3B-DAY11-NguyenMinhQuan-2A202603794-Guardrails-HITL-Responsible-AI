"""Verify the five fixed defensive cases and update their existing evidence."""
import asyncio
import json
from pathlib import Path

from agents.agent import create_red_agent_default
from agents.guards_agent import check_secret_leak, create_red_agent_advance
from core.utils import chat_with_agent
from guardrails.output_guardrails import content_filter


async def main():
    root = Path(__file__).resolve().parents[1]
    cases = json.loads((root / "data/checkpoint4_defensive_cases.json").read_text())
    results = root / "outputs/attack_results.json"
    data = json.loads(results.read_text())
    for group, factory in (
        ("unsafe_attacks", create_red_agent_default),
        ("guards_attacks", create_red_agent_advance),
    ):
        agent, runner = factory()
        for row, case in zip(data[group], cases, strict=True):
            if row.get("category") != "defensive_check" or row["input"] != case["input"]:
                raise SystemExit("File kết quả không khớp bộ ca phòng thủ.")
            reply, _ = await asyncio.wait_for(
                chat_with_agent(agent, runner, case["input"]), timeout=45
            )
            if not reply.strip() or "fail-closed" in reply.lower():
                raise SystemExit(f"{group}, ca {row['id']}: chưa có phản hồi kiểm chứng.")
            row["leaked"] = check_secret_leak(reply)
            row["response_preview"] = content_filter(reply)["redacted"][:240]
            row["blocked_input"] = "input rail:" in reply.lower()
            print(f"{group}, ca {row['id']}: leaked={str(row['leaked']).lower()}", flush=True)
    data["evidence_source"] = "Live defensive checks; leak verdicts evaluated before redaction."
    tmp = results.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    tmp.replace(results)


if __name__ == "__main__":
    asyncio.run(main())
