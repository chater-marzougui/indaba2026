#@title SENTINEL GPU sweep — 18 mandated scenarios, verdict table + decision audit
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
# Why Kaggle: the 1.5B model runs here in fp16 on tensor cores. On the GTX 1660 Ti fp16 was ~7x
# SLOWER than fp32 (Turing's fp16 path is emulated there), so this is the same model, same
# scenarios, same defense — only the hardware changes. Declare that in the technical report.
#
# Expect ~2-3 h for all 21 (a real-model scenario costs 300-1300 s on the laptop; T4 should beat
# that, but budget for it). Kaggle kills an idle session, so don't run anything else meanwhile.

import glob, json, os, shutil, subprocess, sys, time, urllib.request
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
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-e", ".", "transformers>=4.44"], check=True)

# Typer app invoked via -c so we never depend on the console script being on PATH.
def sentinel(*args):
    return subprocess.run([sys.executable, "-c", "from sentinel.cli import app; app()", *args],
                          capture_output=True, text=True)

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

scenarios = sorted(p for g in GROUPS for p in glob.glob(g))
rows, audit = [], []

for path in scenarios:
    name = Path(path).stem
    before = set(glob.glob(f"artifacts/*{name}-http_defense-*"))
    t0 = time.time()
    r = sentinel("run", "--scenario", path, "--defense-url", f"http://127.0.0.1:{PORT}", "--model", MODEL)
    new = sorted(set(glob.glob(f"artifacts/*{name}-http_defense-*")) - before)
    if not new:
        rows.append(f"{name}\tNO-ARTIFACT\t{int(time.time()-t0)}s\trc={r.returncode}")
        continue
    d = json.loads(next(Path(new[-1]).glob("*.summary.json")).read_text())
    rows.append("\t".join(str(x) for x in [
        name, d["task_success"], d["attack_success"], d["critical_violation"],
        d["data_flow_violation"], d["attack_present"], d["steps"], d["termination"],
        f"{int(time.time()-t0)}s"]))

    # The summary's per-step `legitimate` label is the evaluator's own ground truth:
    # false block = we denied something legitimate; missed = we allowed an illegitimate step.
    for dec in d.get("decisions", []):
        legit = dec.get("legitimate")
        if legit and dec["decision"] in DENY:
            audit.append(f"FALSE BLOCK {name} step {dec['step_id']} {dec['tool']} -> {dec['decision']} {dec['reason_codes']}")
        elif legit is False and dec["decision"] not in DENY:
            audit.append(f"MISSED      {name} step {dec['step_id']} {dec['tool']} -> allowed {dec['reason_codes']}")
    print(f"[{name}] task={d['task_success']} atk={d['attack_success']} crit={d['critical_violation']}", flush=True)

Path("/kaggle/working/results.tsv").write_text("\n".join(rows) + "\n")

print("\n=== scenario\ttask\tatk\tcrit\tdataflow\tpresent\tsteps\ttermination\ttime ===")
print("\n".join(rows))
print("\n=== decision audit (evaluator's ground-truth labels) ===")
print("\n".join(audit) or "no false or missed blocks")
print(f"\nfalse/missed: {len(audit)}")
print("\nartifact dirs (download the whole dir from the Output tab if you want them):")
print("\n".join(sorted({p.split('/')[1] for p in glob.glob('artifacts/*-http_defense-*')})))
