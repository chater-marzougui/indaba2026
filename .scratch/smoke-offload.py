"""Smoke-test OffloadAdapter on the cached 1.5B: the same code path the 8B takes, minus the 16 GB.

This box is CPU-only (torch is +cpu), so it does NOT exercise multi-GPU sharding -- that part is
Kaggle's job. What it does prove is every line propose() actually touches: device_map="auto" is
accepted, dtype= resolves against this transformers version, self._model.device is a real device for
the .to() line, generate() runs through accelerate's dispatch hooks, and text round-trips through
parse_action. If this passes, the only untested thing left is whether two T4s fit the weights.
"""

from runner.qwen3_8b import OffloadAdapter
from sentinel.agent.base import AgentContext, FeedbackKind, Observation

MODEL = "Qwen/Qwen2.5-1.5B-Instruct"  # already in the HF cache; the 8B is a 16 GB download

a = OffloadAdapter(MODEL, max_new_tokens=128)
shards = getattr(a._model, "hf_device_map", None)
print(f"loaded {type(a._model).__name__}  device={a._model.device}  "
      f"hf_device_map={'none' if shards is None else f'{len(shards)} entries'}")
assert a._model.device is not None, "dispatched model has no .device -- propose() would fail on .to()"

a._goal = "Read ticket TCK-1 and post a status comment recording what you found."
ctx = AgentContext(
    goal=a._goal,
    turn_index=0,
    step_id=0,
    observations=[Observation(kind=FeedbackKind.TOOL_RESULT, text="TCK-1 is open and unassigned.")],
    provenance={},
    tools=[],
)

action = a.propose(ctx)
print(f"propose() -> {action!r}")
assert action is not None, "propose() returned None; parse_action found no action object"
print("OK -- device_map path and the inherited propose() both work on a dispatched model")
