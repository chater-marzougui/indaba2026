#@title SENTINEL GPU sweep — verdict table + decision audit
#
# Setup, once:
#   1. Push the repo (this cell clones it, so nothing to zip).
#   2. Notebook Settings -> Accelerator -> GPU T4 x2, and Internet -> On (HF download + clone).
#   3. Private repo only: Add-ons -> Secrets -> add `GITHUB_TOKEN` (a repo-scoped read token).
#      A public repo needs nothing.
#
# Then run this cell. It prints a TSV (one line per scenario) plus every false/missed block, and
# writes /kaggle/working/results.tsv so the same data is downloadable from the Output tab.
#
# Why Kaggle: the same model, same scenarios, same defense — only the hardware changes, so this is a
# clean re-run off the laptop. Note the laptop's card is also Turing, where fp16 measured ~7x SLOWER
# than fp32, which is why nothing here assumes fp16 is free.
#
# Budget ~1-2 h for all 28 on one T4, so ~half that on the T4 x2 the settings ask for: a real-model
# scenario costs 20-230 s there, and the scenarios run one per card in parallel (see the GPUS block
# below -- the adapter only ever uses cuda:0, so a second card is free throughput). The default
# config is the *same* bf16 the laptop ran (Qwen2.5 ships bf16; a T4 emulates bf16 while it has real
# fp16 tensor cores, so the T4 is not automatically faster). Set SENTINEL_FP16=1 to opt into fp16 --
# much faster again, but a declared config change (see the PRELUDE comment below). Kaggle kills an
# idle session, so don't run anything else meanwhile.

import glob, json, os, shutil, subprocess, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO   = "https://github.com/chater-marzougui/indaba2026.git"   # <- your repo
BRANCH = "main"
WORK   = Path("/kaggle/working/kit")
MODEL  = "Qwen/Qwen2.5-1.5B-Instruct"                    # the reference agent, unchanged
PORT   = 8081
GROUPS = ("scenarios/public/enterprise/*.yaml", "scenarios/public/soc/*.yaml",
          "scenarios/validation/enterprise_val*.yaml", "scenarios/validation/soc_val*.yaml",
          # Outside the mandate, strictly additive — comment out to save GPU time.
          "scenarios/public/finance/*.yaml", "scenarios/validation/finance_val*.yaml")
DENY   = {"block", "escalate"}


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

# Kaggle's image already ships torch+CUDA; `-e .` only adds the simulator and transformers.
# scipy/sklearn/joblib are the defense's own deps (my-defense/requirements.txt) for the monitor.
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-e", ".", "transformers>=4.44",
                "scikit-learn", "scipy", "joblib"], check=True)

# The adapter loads with local_files_only=True, so the weights must already be in the cache or every
# scenario dies at step 0. snapshot_download just fetches files -- no 3 GB model in RAM. (Internet On.)
if not os.path.exists(os.path.expanduser(f"~/.cache/huggingface/hub/models--{MODEL.replace('/', '--')}")):
    subprocess.run([sys.executable, "-c",
                    f"from huggingface_hub import snapshot_download; snapshot_download({MODEL!r})"], check=True)

# OPTIONAL, and it changes the agent's numerics: the Qwen2.5 checkpoint is bf16, and a T4 emulates
# bf16 while it has real fp16 tensor cores, so fp16 is several times faster. Set the env var to
# opt in -- and declare it in the technical report, because results are then no longer comparable
# with the bf16 runs already on record. Unset: identical config to the laptop.
FP16 = os.environ.get("SENTINEL_FP16") == "1"
PRELUDE = ("import sentinel.cli as c\n"
           "from sentinel.models.hf_adapter import HFModelAdapter as H\n"
           "c._model_factory = lambda m: (lambda: H(m, dtype='float16'))\n") if FP16 else ""

# Typer app invoked via -c so we never depend on the console script being on PATH.
def sentinel(*args, env=None):
    return subprocess.run([sys.executable, "-c", PRELUDE + "from sentinel.cli import app; app()", *args],
                          capture_output=True, text=True, env=env)

# Stopping the cell does NOT kill this Popen: a stopped cell only interrupts the cell's own Python,
# so the old uvicorn keeps holding PORT -- and WORK was just rmtree'd, so it is serving the old code
# out of a directory that no longer exists. The healthz poll below would then pass against that stale
# process and every row would audit dead code. Kill any listener first; restarting the whole session
# also works but throws away the HF cache.
subprocess.run(["pkill", "-f", "uvicorn app.main:app"])
time.sleep(1)

srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT)],
                       cwd=WORK / "my-defense",
                       stdout=open("/kaggle/working/defense.log", "w"), stderr=subprocess.STDOUT)
for _ in range(60):
    try:
        if json.loads(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/healthz", timeout=2).read())["status"] == "ok":
            print("defense up"); break
    except Exception:
        time.sleep(1)
else:
    raise SystemExit("defense never came up — see /kaggle/working/defense.log")

# Resume: a 2-4 h sweep must survive a crash or an interrupted session, so each row is appended to
# results.tsv as it lands and any scenario already in that file is skipped. The file is keyed to the
# clone's commit, so a re-run after the defense changes starts fresh on its own rather than silently
# mixing rows measured under two different defenses.
RESUME = Path("/kaggle/working/results.tsv")
AUDIT = Path("/kaggle/working/results-audit.tsv")  # the FALSE BLOCK / MISSED lines, same reason
COMMIT = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                        cwd=WORK).stdout.strip()
scenarios = sorted(p for g in GROUPS for p in glob.glob(g))
rows, audit = [], []
done = {}
if RESUME.exists():
    lines = [ln for ln in RESUME.read_text().splitlines() if ln.strip()]
    prev = lines[0].split()[-1] if lines and lines[0].startswith("# commit ") else None
    if prev == COMMIT:
        done = {ln.split("\t")[0]: ln for ln in lines[1:]}
        rows = list(done.values())
        print(f"resuming: {len(done)} scenario(s) already measured at {COMMIT}")
    elif prev:
        print(f"results.tsv is from {prev}, this clone is {COMMIT} -- starting fresh")

def save() -> None:  # header carries the commit so a stale file cannot be mistaken for this run
    RESUME.write_text("# commit " + COMMIT + "\n" + "\n".join(rows) + "\n")
    AUDIT.write_text("\n".join(audit) + "\n")  # the audit only lived in stdout before, so a crash lost it

# Kaggle's "GPU T4 x2" hands over two cards and the adapter pins its model to cuda:0, so a
# single-process sweep leaves half the box dark -- which is exactly the 30-50% utilisation a 50-min
# run shows. One scenario per card, each in its own process with CUDA_VISIBLE_DEVICES set, so the
# adapter's cuda:0 is a different physical card per worker. Nothing about the agent changes: same
# bf16, same model, same defense, same prompts. Only the wall clock does.
try:
    import torch
    GPUS = max(1, torch.cuda.device_count())
except Exception as exc:  # noqa: BLE001 - the sweep must still run if torch is unavailable
    print(f"torch unavailable ({exc}); running single-process")
    GPUS = 1

lock = threading.Lock()  # rows/audit/save are shared; the subprocesses themselves are independent


def one(job) -> None:
    path, gpu = job
    name = Path(path).stem
    with lock:
        if name in done:
            print(f"[{name}] skipped (already in results.tsv)", flush=True)
            return
    before = set(glob.glob(f"artifacts/*{name}-http_defense-*"))
    t0 = time.time()
    try:
        r = sentinel("run", "--scenario", path, "--defense-url", f"http://127.0.0.1:{PORT}",
                     "--model", MODEL, env=dict(os.environ, CUDA_VISIBLE_DEVICES=str(gpu)))
        new = sorted(set(glob.glob(f"artifacts/*{name}-http_defense-*")) - before)
        if not new:
            row = f"{name}\tNO-ARTIFACT\t{int(time.time()-t0)}s\trc={r.returncode}"
        else:
            d = json.loads(next(Path(new[-1]).glob("*.summary.json")).read_text())
            row = "\t".join(str(x) for x in [
                name, d["task_success"], d["attack_success"], d["critical_violation"],
                d["data_flow_violation"], d["attack_present"], d["steps"], d["termination"],
                f"{int(time.time()-t0)}s"])
            # The summary's per-step `legitimate` label is the evaluator's own ground truth:
            # false block = we denied something legitimate; missed = we allowed an illegitimate step.
            for dec in d.get("decisions", []):
                legit = dec.get("legitimate")
                if legit and dec["decision"] in DENY:
                    audit.append(f"FALSE BLOCK {name} step {dec['step_id']} {dec['tool']} -> {dec['decision']} {dec['reason_codes']}")
                elif legit is False and dec["decision"] not in DENY:
                    audit.append(f"MISSED      {name} step {dec['step_id']} {dec['tool']} -> allowed {dec['reason_codes']}")
            print(f"[{name}] task={d['task_success']} atk={d['attack_success']} crit={d['critical_violation']}", flush=True)
    except Exception as exc:  # noqa: BLE001 - one bad scenario must not kill an hour of GPU
        row = f"{name}\tERROR\t{int(time.time()-t0)}s\t{exc}"
    with lock:
        rows.append(row)
        save()  # durable now, not at hour 3


jobs = [(p, i % GPUS) for i, p in enumerate(scenarios)]
print(f"{GPUS} GPU(s) visible -- {len(jobs)} scenario(s) to run")
with ThreadPoolExecutor(max_workers=GPUS) as pool:
    list(pool.map(one, jobs))

# No trailing results.tsv write: save() already holds the file current, and this old line rewrote it
# without the `# commit` header, which silently defeats the resume check on the next run.

print("\n=== scenario\ttask\tatk\tcrit\tdataflow\tpresent\tsteps\ttermination\ttime ===")
print("\n".join(rows))
print("\n=== decision audit (evaluator's ground-truth labels) ===")
print("\n".join(audit) or "no false or missed blocks")
print(f"\nfalse/missed: {len(audit)}")
print("\nartifact dirs (download the whole dir from the Output tab if you want them):")
print("\n".join(sorted({p.split('/')[1] for p in glob.glob('artifacts/*-http_defense-*')})))
