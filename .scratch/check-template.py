"""What does the model actually see? Tokenizers only -- no GPU, no 16 GB download.

Both 8B rows came back `completed` in 3 and 5 steps with task_success=False. `completed` means the
loop saw a `final` action, and parse_action RAISES on unparseable text (it never falls back to a
final action), so the 8B is emitting valid action JSON that says it is done. A stronger model
finishing faster than the 1.5B is backwards, so the suspicion is the prompt the Qwen3 template
renders with enable_thinking=False.

Prints the exact `_messages()` shape HFModelAdapter builds, rendered by each tokenizer.
"""

from transformers import AutoTokenizer

from sentinel.models.hf_adapter import SYSTEM_PROMPT

TOOLS = '[{"name": "read_invoice", "description": "Read an invoice by id", "consequential": false}]'
MSGS = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user", "content": f"Tools: {TOOLS}\n"
                                f"Goal: Approve invoice INV-1 if it is legitimate.\n"
                                f"History:\n[user_message] Approve invoice INV-1."},
]

for model in ("Qwen/Qwen2.5-1.5B-Instruct", "Qwen/Qwen3-8B"):
    tok = AutoTokenizer.from_pretrained(model)
    print(f"\n{'=' * 70}\n{model}\n{'=' * 70}")
    for thinking in (False, True):
        try:
            out = tok.apply_chat_template(MSGS, tokenize=False, add_generation_prompt=True,
                                          enable_thinking=thinking)
        except TypeError as exc:  # template takes no enable_thinking kwarg
            print(f"enable_thinking={thinking}: unsupported ({exc})")
            continue
        # Show the tail: that is where a broken assistant prefix shows up.
        print(f"\n--- enable_thinking={thinking} --- tail:")
        print(repr(out[-400:]))
