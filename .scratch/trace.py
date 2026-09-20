"""One-glance decision trace for a scenario's newest run.

Usage: uv run python .scratch/trace.py <name-substring> [--full]
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def clip(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--full", action="store_true", help="print full event payloads")
    args = ap.parse_args()

    hits = [p for p in (ROOT / "artifacts").glob(f"*{args.name}*/*.jsonl")]
    if not hits:
        print("no run found")
        return 1
    path = max(hits, key=lambda p: p.stat().st_mtime)
    print(f"# {path.relative_to(ROOT)}  ({path.stat().st_size} B)")
    summary = path.with_name(path.name.replace(".jsonl", ".summary.json"))
    if summary.exists():
        d = json.loads(summary.read_text(encoding="utf-8"))
        print("# verdict:", {k: d.get(k) for k in ("task_success", "attack_success", "critical_violation",
                                                   "data_flow_violation", "attack_present", "steps", "termination")})
    for line in path.read_text(encoding="utf-8").splitlines():
        ev = json.loads(line)
        t, p = ev["type"], ev.get("payload", {})
        if args.full:
            print(f"[{ev['step_id']:>2}] {t}: {json.dumps(p)[:2000]}")
            continue
        if t == "defense_decision":
            a = p.get("action") or {}
            arg = json.dumps(a.get("arguments") or {})[:110]
            print(f"[{ev['step_id']:>2}] {p.get('decision','?'):<8} {a.get('type','')}/{a.get('tool') or '':<22} "
                  f"{','.join(p.get('reason_codes') or []):<28} {arg}")
            if a.get("content"):
                print(f"      content: {clip(a['content'], 140)}")
        elif t == "model_output":
            print(f"[{ev['step_id']:>2}] MODEL  final={p.get('final')} {clip(p.get('content',''), 140)}")
        elif t == "retrieval_result":
            print(f"[{ev['step_id']:>2}] RESULT {clip(p.get('content') or p.get('text') or json.dumps(p), 140)}")
        elif t == "user_message":
            print(f"[{ev['step_id']:>2}] GOAL   {clip(p.get('text',''), 160)}")
        elif t == "tool_request":
            print(f"[{ev['step_id']:>2}] CALL   {p.get('tool')} {clip(json.dumps(p.get('arguments', {})), 110)}")
        elif t in ("task_success", "blocked", "escalated", "human_confirmation"):
            print(f"[{ev['step_id']:>2}] {t.upper()} {clip(json.dumps(p), 160)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
