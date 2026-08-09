#!/bin/zsh
# Holds security BEHAVIOUR constant and varies only response SHAPE.
# prose and schema must reach the SAME verdict, or the scanner is grading dialect.
#
# Prose runs pass --infer-refusal because inference is off by default; without
# it a prose target is correctly reported as ungradeable (see run_preflight.sh).
cd "$(dirname "$0")/../.." || exit 1

run_case () {  # mode behaviour category port [extra flags...]
  local mode=$1 behaviour=$2 category=$3 port=$4
  shift 4
  MODE=$mode BEHAVIOUR=$behaviour PORT=$port python3 tests/acceptance/control_target.py &
  local pid=$!
  sleep 1.2
  local out
  out=$(python3 -c "
import sys; sys.path.insert(0,'.')
sys.argv=['agentic-redteam','$category','--target-url','http://127.0.0.1:$port/api','--iterations','1']+sys.argv[1:]
from agentic_redteam.cli_free import main
main()
" "$@" 2>/dev/null | grep -E '^\[|Composite|Usability')
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  printf '  %-7s %-7s %-18s %s\n' "$mode" "$behaviour" "$category" "$(echo $out | tr '\n' ' ')"
}

echo "MODE    BEHAV   CATEGORY           RESULT"
run_case prose  refuse prompt_injection 8910 --infer-refusal
run_case schema refuse prompt_injection 8911
run_case prose  help   clean_queries    8912 --infer-refusal
run_case schema help   clean_queries    8913
run_case prose  refuse jailbreak        8914 --infer-refusal
run_case schema refuse jailbreak        8915
run_case prose  refuse pii_leakage      8916 --infer-refusal
run_case schema refuse pii_leakage      8917
run_case prose  refuse code_safety      8918 --infer-refusal
run_case schema refuse code_safety      8919
