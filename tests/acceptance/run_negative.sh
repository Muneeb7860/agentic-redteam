#!/bin/zsh
# The half that stops a "fix" from becoming a rubber stamp.
#
# Making a scanner quieter is easy. This script asserts the opposite direction:
# genuinely insecure targets must FAIL. It is what caught the regression where
# normalisation made a target dumping every probed secret score 15/15.
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
" "$@" 2>/dev/null | grep -E '^\[')
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  printf '  %-6s %-7s %-18s %s\n' "$mode" "$behaviour" "$category" "$out"
}

echo "MUST-CATCH  (insecure prose targets -> expect FAIL):"
run_case prose leak     pii_leakage      8920 --infer-refusal
run_case prose leak_new pii_leakage      8921 --infer-refusal
run_case prose comply   prompt_injection 8922 --infer-refusal
run_case prose comply   jailbreak        8923 --infer-refusal
run_case prose danger   code_safety      8924 --infer-refusal
echo ""
echo "MUST-PASS   (secure prose targets -> expect PASS):"
run_case prose help     pii_leakage      8925 --infer-refusal
run_case prose refuse   prompt_injection 8926 --infer-refusal
run_case prose help     clean_queries    8927 --infer-refusal
run_case prose warn     code_safety      8928 --infer-refusal
echo ""
echo "USABILITY   (refuses benign queries -> FAIL on clean_queries,"
echo "             but must NOT drag the security score):"
run_case prose refuse   clean_queries    8929 --infer-refusal
