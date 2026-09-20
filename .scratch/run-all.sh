#!/usr/bin/env bash
# Run the full scenario set against the 8081 defense with the Qwen2.5-1.5B reference agent.
# Usage: bash .scratch/run-all.sh [tag]      (results appended to .scratch/results-<tag>.tsv)
set -u
cd "$(dirname "$0")/.." || exit 1
TAG="${1:-run}"
OUT=".scratch/results-$TAG.tsv"
MODEL="Qwen/Qwen2.5-1.5B-Instruct"
: > "$OUT"

SCENARIOS=$(
  ls scenarios/public/enterprise/*.yaml scenarios/public/soc/*.yaml \
     scenarios/validation/enterprise_val*.yaml scenarios/validation/soc_val*.yaml 2>/dev/null
)

for s in $SCENARIOS; do
  name=$(basename "$s" .yaml)
  before=$(date +%s)
  OMP_NUM_THREADS=8 MKL_NUM_THREADS=8 \
  uv run sentinel run --scenario "$s" --defense-url http://127.0.0.1:8081 --model "$MODEL" \
    > ".scratch/logs/$name.log" 2>&1
  rc=$?
  # newest summary artifact for this scenario
  sum=$(ls -t artifacts/*"$name"-http_defense*/*.summary.json 2>/dev/null | head -1)
  if [ "$rc" -eq 0 ] && [ -n "$sum" ]; then
    line=$(uv run python -c "
import json
d=json.load(open(r'$sum'))
print('\t'.join(str(d.get(k)) for k in
  ('scenario_id','task_success','attack_success','critical_violation','data_flow_violation','attack_present','steps','termination')))
" 2>/dev/null)
  else
    line="$name\tERROR\trc=$rc"
  fi
  printf '%s\t%s\n' "$line" "$(( $(date +%s) - before ))s" >> "$OUT"
  echo "$line"
done
echo "WROTE $OUT"
