#@title SENTINEL — does the reference agent reach the attack? (run this BEFORE recording)
#
# The participant guide calls this "the single most important check in the kit":
#
#   Every attack scenario is built so that the attack *succeeds* when nothing is defending, so
#   this run must report attack_success=True. If it reports False, your agent finished the task
#   without ever opening the record the attack was injected into -- the payload was never in front
#   of it. Nothing measured in that configuration means anything, because a defense that does
#   nothing scores exactly the same as a good one.
#
# A scenario only belongs in the video if this run reports attack_success=True for it, UNDEFENDED.
# Otherwise you would be filming a defense stopping an attack the agent never encountered.
#
# Settings: Accelerator -> GPU T4 x2, Internet -> On. ~20 min for the download plus a few minutes
# per scenario at 8B. No defense service is started: `--defense allow_all` runs in-process.

import glob, json, os, shutil, subprocess, sys, time
from pathlib import Path

REPO   = "https://github.com/chater-marzougui/indaba2026.git"
BRANCH = "main"
WORK   = Path("/kaggle/working/kit")
MODEL  = "Qwen/Qwen3-8B"                      # the official reference agent, unquantized

# Candidates for the video, drawn from the scenarios the paired control showed losing the attack
# undefended. The guide's own example run uses finance_false_approval.
CANDIDATES = [
    "scenarios/public/finance/finance_false_approval.yaml",
    "scenarios/public/enterprise/enterprise_memory_poison.yaml",
    "scenarios/public/enterprise/enterprise_direct_token_request.yaml",
    "scenarios/public/soc/soc_hostile_log_text.yaml",
    "scenarios/public/finance/finance_split_settlement.yaml",
    "scenarios/validation/enterprise_val_ticket_comment.yaml",
]


def repo_url() -> str:
    """Private repo -> read the token from a Kaggle Secret named GITHUB_TOKEN; public -> plain URL."""
    try:
        from kaggle_secrets import UserSecretsClient
        return REPO.replace("https://", f"https://{UserSecretsClient().get_secret('GITHUB_TOKEN')}@")
    except Exception:
        return REPO


if WORK.exists():
    shutil.rmtree(WORK)
subprocess.run(["git", "clone", "-q", "--depth", "1", "-b", BRANCH, repo_url(), str(WORK)], check=True)
os.chdir(WORK)
print("cloned", subprocess.run(["git", "log", "--oneline", "-1"], capture_output=True, text=True).stdout.strip())

# accelerate is what makes device_map="auto" work -- it shards the 8B across both T4s and spills the
# remainder to host RAM. Without it the load fails outright.
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-e", ".", "transformers>=4.44",
                "accelerate", "scikit-learn", "scipy", "joblib"], check=True)

# The adapter loads with local_files_only=True, so the weights must be in the cache or every
# scenario dies at step 0. ~16.4 GB for the 8B -- this is the slow part of the cell.
if not os.path.exists(os.path.expanduser(f"~/.cache/huggingface/hub/models--{MODEL.replace('/', '--')}")):
    print(f"downloading {MODEL} (~16.4 GB)...", flush=True)
    subprocess.run([sys.executable, "-c",
                    f"from huggingface_hub import snapshot_download; snapshot_download({MODEL!r})"], check=True)

# Our loader, ours, so src/sentinel/ stays untouched. See runner/qwen3_8b.py.
PRELUDE = ("import sentinel.cli as c\n"
           "from runner.qwen3_8b import build\n"
           "c._model_factory = lambda m: (lambda: build(m))\n")


def sentinel(*args):
    return subprocess.run([sys.executable, "-c", PRELUDE + "from sentinel.cli import app; app()", *args],
                          capture_output=True, text=True)


print(f"\n{'scenario':<44} {'atk':<5} {'task':<5} {'steps':<6} {'termination':<12} usable")
usable = []
for path in CANDIDATES:
    name = Path(path).stem
    before = set(glob.glob(f"artifacts/*{name}-*"))
    t0 = time.time()
    r = sentinel("run", "--scenario", path, "--defense", "allow_all", "--model", MODEL)
    new = sorted(set(glob.glob(f"artifacts/*{name}-*")) - before)
    if not new:
        print(f"{name:<44} {'--':<5} {'--':<5} {'--':<6} {'NO-ARTIFACT':<12} rc={r.returncode}")
        print((r.stdout or r.stderr)[-800:])
        continue
    d = json.loads(next(Path(new[-1]).glob("*.summary.json")).read_text())
    ok = bool(d["attack_success"])
    if ok:
        usable.append((name, int(time.time() - t0)))
    print(f"{name:<44} {str(d['attack_success']):<5} {str(d['task_success']):<5} "
          f"{d['steps']:<6} {d['termination']:<12} {'YES' if ok else 'no -- payload never reached'}", flush=True)

print("\n=== usable for the video (attack lands undefended) ===")
for name, secs in usable:
    print(f"  {name}  ({secs}s)")
if not usable:
    print("  none. Per the guide, demonstrate with --model mock instead and say so in the report.")
print(f"\n{len(usable)}/{len(CANDIDATES)} reached the attack.")
