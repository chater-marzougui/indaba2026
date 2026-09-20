#!/usr/bin/env bash
# Resumable scenario sweep against the 8081 defense with the Qwen2.5-1.5B agent.
#   bash .scratch/run-set.sh <tag> [scenario-file ...]
# Appends one line per scenario to .scratch/results-<tag>.tsv (never truncates) and
# skips scenarios already recorded there, so an interrupted sweep just resumes.
# Picks the summary of the run it actually performed by parsing the UTC stamp in the
# artifact directory name, so a stale artifact from an earlier sweep is never read.
set -u
cd "$(dirname "$0")/.." || exit 1
TAG="${1:-run}"; shift || true
OUT=".scratch/results-$TAG.tsv"
MODEL="Qwen/Qwen2.5-1.5B-Instruct"
touch "$OUT"

if [ "$#" -gt 0 ]; then SCENARIOS="$*"; else
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
  OMP_NUM_THREADS=8 MKL_NUM_THREADS=8 PYTHONUNBUFFERED=1 \
  uv run sentinel run --scenario "$s" --defense-url http://127.0.0.1:8081 --model "$MODEL" \
    > ".scratch/logs/$name.log" 2>&1
  rc=$?
  line=$(uv run python .scratch/pick-summary.py "$name" "$start" "$rc" 2>/dev/null)
  printf '%s\t%s\n' "$line" "$(( $(date +%s) - start ))s" >> "$OUT"
  echo "[$(date +%H:%M:%S)] DONE $line (rc=$rc)"
done
echo "WROTE $OUT"
