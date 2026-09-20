"""Print the TSV line for one scenario run: the summary of the run that just finished.

Usage: uv run python .scratch/pick-summary.py <scenario-name> <start-epoch> <rc>

The artifact directory name carries the run's UTC start stamp
(eval-run-<scenario>-http_defense-<YYYYMMDDTHHMMSSZ>), so a directory whose stamp is at
or after the epoch we passed is this run's, never a leftover from an earlier sweep.
"""

import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEYS = (
    "scenario_id",
    "task_success",
    "attack_success",
    "critical_violation",
    "data_flow_violation",
    "attack_present",
    "steps",
    "termination",
)


def stamp_of(dirname: str) -> float | None:
    tail = dirname.rsplit("-", 1)[-1]  # 20260920T135528Z
    try:
        return dt.datetime.strptime(tail, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return None


def main() -> int:
    name, start, rc = sys.argv[1], float(sys.argv[2]), sys.argv[3]
    hits = []
    for d in (ROOT / "artifacts").glob(f"*{name}-http_defense*"):
        st = stamp_of(d.name)
        if st is not None and st >= start - 90:  # allow for clock skew between bash and UTC stamp
            for summary in d.glob("*.summary.json"):
                hits.append((st, summary))
    if not hits:
        print(f"{name}\tERROR\trc={rc}\tno-artifact")
        return 1
    summary = max(hits, key=lambda t: t[0])[1]
    data = json.loads(summary.read_text(encoding="utf-8"))
    print("\t".join(str(data.get(k)) for k in KEYS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
