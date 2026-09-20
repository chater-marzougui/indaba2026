#!/usr/bin/env bash
# Restart the defense service on :8081 with a clean bytecode cache.
set -u
cd "$(dirname "$0")/.." || exit 1
PID=$(netstat -ano | grep -E 'TCP.*127\.0\.0\.1:8081.*LISTENING' | awk '{print $NF}' | head -1)
[ -n "${PID:-}" ] && taskkill //F //PID "$PID" >/dev/null 2>&1
rm -rf my-defense/app/__pycache__
cd my-defense || exit 1
{
  .venv/Scripts/python.exe -m uvicorn app.main:app --port 8081 >../.scratch/defense.log 2>&1 &
}
for _ in $(seq 1 40); do
  sleep 0.5
  if curl -sf http://127.0.0.1:8081/healthz >/dev/null 2>&1; then
    echo "defense up on :8081"
    exit 0
  fi
done
echo "FAILED to start; log tail:"
tail -20 ../.scratch/defense.log
exit 1
