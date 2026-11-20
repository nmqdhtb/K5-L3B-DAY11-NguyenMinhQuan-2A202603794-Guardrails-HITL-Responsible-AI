"""Kiểm tra cấu trúc bằng chứng Checkpoint 4 đã ghi trong outputs/."""
import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[1] / "outputs" / "attack_results.json"


def validate(data):
    if not isinstance(data, dict):
        raise ValueError("Nội dung gốc phải là một object JSON.")
    for field in ("llm_provider", "llm_model"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise ValueError(f"Thiếu {field}.")
    for group in ("unsafe_attacks", "guards_attacks"):
        rows = data.get(group)
        if not isinstance(rows, list):
            raise ValueError(f"Thiếu danh sách {group}.")
        prompts = set()
        for i, row in enumerate(rows, 1):
            if not isinstance(row, dict) or not isinstance(row.get("leaked"), bool):
                raise ValueError(f"{group}, dòng {i}: cần trường leaked kiểu boolean.")
            prompt = row.get("input")
            if not isinstance(prompt, str) or not prompt.strip() or prompt.lstrip().startswith("TODO:"):
                raise ValueError(f"{group}, dòng {i}: thiếu nội dung thử nghiệm.")
            prompts.add(prompt.strip())
        if len(prompts) < 5:
            raise ValueError(f"{group}: cần ít nhất 5 prompt khác nhau.")


if __name__ == "__main__":
    try:
        validate(json.loads(RESULTS.read_text(encoding="utf-8")))
    except FileNotFoundError:
        raise SystemExit("Thiếu outputs/attack_results.json.")
    except (ValueError, OSError) as error:
        raise SystemExit(str(error))
    print("Cấu trúc kết quả Checkpoint 4 hợp lệ.")
