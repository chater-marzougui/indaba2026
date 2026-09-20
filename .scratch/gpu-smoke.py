"""Does the 1660 Ti run this model, at which dtype, and how fast?

Usage: .venv-gpu/Scripts/python.exe .scratch/gpu-smoke.py [--path <model dir or repo id>]
"""

import argparse
import time

import torch

PROMPT = "Reply with exactly one JSON object and nothing else: {\"type\": \"respond\""


def timed(model, tok, n=48):
    inputs = tok([PROMPT], return_tensors="pt").to(model.device)
    t0 = time.perf_counter()
    out = model.generate(**inputs, max_new_tokens=n, do_sample=False)
    dt = time.perf_counter() - t0
    text = tok.decode(out[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)
    return dt, n / dt, text.strip()[:70]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="Qwen/Qwen2.5-1.5B-Instruct")
    args = ap.parse_args()

    print(f"torch {torch.__version__}")
    print(f"cuda available: {torch.cuda.is_available()}")
    if not torch.cuda.is_available():
        return 1
    print(f"device: {torch.cuda.get_device_name(0)}  capability: {torch.cuda.get_device_capability(0)}")
    print(f"vram: {torch.cuda.get_device_properties(0).total_memory / 2**30:.1f} GiB")

    from transformers import AutoConfig, AutoModelForCausalLM, AutoTokenizer

    cfg = AutoConfig.from_pretrained(args.path, local_files_only=True)
    print(f"checkpoint dtype in config: {getattr(cfg, 'dtype', None) or getattr(cfg, 'torch_dtype', None)}")
    tok = AutoTokenizer.from_pretrained(args.path, local_files_only=True)

    for dtype in ("auto", "float16"):
        try:
            model = AutoModelForCausalLM.from_pretrained(args.path, local_files_only=True, dtype=dtype)
            model = model.to("cuda")
            torch.cuda.synchronize()
            warm = timed(model, tok, n=4)
            dt, tps, text = timed(model, tok, n=48)
            print(f"\ndtype={dtype:<8} -> model.dtype={model.dtype}  {tps:.1f} tok/s  ({dt:.1f}s/48)  {text!r}")
            del model
            torch.cuda.empty_cache()
        except Exception as exc:
            print(f"\ndtype={dtype:<8} -> FAILED: {type(exc).__name__}: {str(exc)[:200]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
