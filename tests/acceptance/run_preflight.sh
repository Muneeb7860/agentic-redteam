#!/bin/zsh
# Inference is OFF by default. A target that declares no {status} must be
# reported as UNGRADEABLE (exit 2), not silently graded.
#
# This is the guard against the original defect's worst form: a safe agent
# receiving an authoritative-looking F because `r.status === "blocked"` is
# false when there is no status field at all.
cd "$(dirname "$0")/../.." || exit 1

probe () {  # mode label [extra flags...]
  local mode=$1 label=$2
  shift 2
  MODE=$mode BEHAVIOUR=refuse PORT=8940 python3 tests/acceptance/control_target.py &
  local pid=$!
  sleep 1.2
  local out rc
  out=$(python3 -c "
import sys; sys.path.insert(0,'.')
sys.argv=['agentic-redteam','prompt_injection','--target-url','http://127.0.0.1:8940/api','--iterations','1']+sys.argv[1:]
from agentic_redteam.cli_free import main
raise SystemExit(main())
" "$@" 2>/dev/null)
  rc=$?
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  echo "--- $label (exit $rc) ---"
  echo "$out" | grep -E 'Cannot grade|Pick one|--infer-refusal|Composite|^\[' | head -6
  echo ""
}

probe prose  "prose target, default (must refuse to grade, exit 2)"
probe prose  "prose target, --infer-refusal (must grade)" --infer-refusal
probe schema "contract-speaking target, default (must grade)"
