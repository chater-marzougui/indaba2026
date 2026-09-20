"""Throughput for the shape the agent actually uses: ~2k-token prompt, ~120-token JSON reply.

Usage: .venv-gpu/Scripts/python.exe .scratch/gpu-tps.py [--dtype auto|float16|bfloat16]
"""

import argparse
import time

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
FILLER = (
    '{"name": "email_search", "description": "Search the mailbox", "consequential": false, '
    '"arguments": {"query": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["query"]} '
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dtype", default="float16")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--new", type=int, default=120)
    ap.add_argument("--prompt-tokens", type=int, default=2000)
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(MODEL, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(MODEL, local_files_only=True, dtype=args.dtype).to(args.device)
    print(f"device={args.device} dtype={args.dtype} -> {model.dtype}")

    body = (FILLER * 400)[: args.prompt_tokens * 4]
    ids = tok(body, return_tensors="pt").input_ids[:, : args.prompt_tokens].to(args.device)
    print(f"prompt tokens: {ids.shape[-1]}")

    model.generate(**{"input_ids": ids}, max_new_tokens=8, do_sample=False)  # warm up

    sync = torch.cuda.synchronize if args.device == "cuda" else lambda: None
    sync()
    t0 = time.perf_counter()
    out = model.generate(input_ids=ids, max_new_tokens=args.new, do_sample=False)
    sync()
    dt = time.perf_counter() - t0
    n = out.shape[-1] - ids.shape[-1]
    print(f"DECODE {n/(dt):.1f} tok/s  ({n} tokens in {dt:.2f}s incl. prefill)")
    print(f"PER-CALL cost of a {args.new}-token reply: {dt:.2f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
