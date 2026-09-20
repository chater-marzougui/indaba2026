"""Run the reference agent on hardware that cannot hold it.

``HFModelAdapter.__init__`` ends with ``model.to(resolved_device)``, which needs the whole
checkpoint on one device. Qwen3-8B in bf16 is ~16.4 GB of weights: more than a T4's ~14.6 GB
usable, far more than a laptop card. ``device_map="auto"`` lets accelerate spread the same
weights across every visible GPU and spill whatever is left into host RAM.

This is plumbing, not a different agent. Same checkpoint, same dtype, same system prompt, same
tools, no safety instructions added -- the participant guide puts precision, quantization, device
placement and decode budget explicitly on the participant's side of the line
(``docs/participant-guide.md``, "How you may run it"). Declare it in the report's "how we ran the
reference agent" paragraph.

Wired in through ``sentinel.cli._model_factory``, the same hook the CLI itself uses, so nothing
under ``src/sentinel/`` is modified::

    python -c "import sentinel.cli as c; from runner.qwen3_8b import build; \\
               c._model_factory = lambda m: (lambda: build(m)); \\
               from sentinel.cli import app; app()" \\
        run --scenario <path> --defense allow_all --model qwen3-8b
"""

from __future__ import annotations

from sentinel.models.hf_adapter import DEFAULT_MODEL, HFModelAdapter

ALIASES = ("qwen3-8b", "qwen3", "qwen", "default")


class OffloadAdapter(HFModelAdapter):
    """``HFModelAdapter`` that shards across devices instead of pinning to one."""

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL,
        dtype: str = "bfloat16",
        max_new_tokens: int = 768,
        max_context_chars: int = 12_000,
        enable_thinking: bool = False,
        **_ignored: object,
    ) -> None:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
        self._model = AutoModelForCausalLM.from_pretrained(
            model_path, local_files_only=True, dtype=getattr(torch, dtype), device_map="auto"
        )
        # Mirrors the state HFModelAdapter.__init__ sets. Not inherited via super() because that
        # would load the full checkpoint onto a single device first -- the thing we are avoiding.
        self._max_new_tokens = max_new_tokens
        self._max_context_chars = max_context_chars
        self._enable_thinking = enable_thinking
        self._goal = ""
        self._tools: list[dict[str, object]] = []


def build(model: str = DEFAULT_MODEL, dtype: str = "bfloat16") -> OffloadAdapter:
    """``--model`` argument -> adapter, with the same aliases ``sentinel.cli._model_factory`` uses.

    ``dtype`` is separate because it is a declared config change, not a model choice: bfloat16 is the
    faithful default, float16 is the escape hatch when a card emulates bf16 (Turing has no native
    support for it). Whichever you pick, use it for the check and the recording both.
    """
    return OffloadAdapter(DEFAULT_MODEL if model in ALIASES else model, dtype=dtype)
