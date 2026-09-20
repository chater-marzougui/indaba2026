#!/usr/bin/env bash
# Same sweep as run-set.sh but on the CUDA venv (.venv-gpu) instead of the CPU .venv.
#   bash .scratch/run-set-gpu.sh <tag> [scenario-file ...]
# Resumable: appends to .scratch/results-<tag>.tsv and skips scenarios already there.
# ONE model process at a time -- a second instance on this 6 GiB card causes WDDM paging.
set -u
cd "$(dirname "$0")/.." || exit 1
TAG="${1:-gpu}"; shift || true
OUT=".scratch/results-$TAG.tsv"
SENTINEL=".venv-gpu/Scripts/sentinel.exe"
MODEL="Qwen/Qwen2.5-1.5B-Instruct"
[ -x "$SENTINEL" ] || { echo "no $SENTINEL"; exit 1; }
touch "$OUT"

if [ "$#" -gt 0 ]; then SCENARIOS="$*"; else
  # attacked scenarios first: they are the only ones that can exercise the defense
  SCENARIOS=$(ls scenarios/public/enterprise/*.yaml scenarios/public/soc/*.yaml \
                 scenarios/validation/enterprise_val*.yaml scenarios/validation/soc_val*.yaml 2>/dev/null)
fi

for s in $SCENARIOS; do
  name=$(basename "$s" .yaml)
  if grep -q "^$name	" "$OUT" 2>/dev/null; then
    echo "[$(date +%H:%M:%S)] skip $name (already in $OUT)"
    continue
  fi
  start=$(date +%s)
  echo "[$(date +%H:%M:%S)] RUN  $name"
  PYTHONUNBUFFERED=1 "$SENTINEL" run --scenario "$s" --defense-url http://127.0.0.1:8081 \
    --model "$MODEL" > ".scratch/logs/gpu-$name.log" 2>&1
  rc=$?
  line=$(uv run python .scratch/pick-summary.py "$name" "$start" "$rc" 2>/dev/null)
  printf '%s\t%s\n' "$line" "$(( $(date +%s) - start ))s" >> "$OUT"
  echo "[$(date +%H:%M:%S)] DONE $line (rc=$rc)"
done
echo "WROTE $OUT"
