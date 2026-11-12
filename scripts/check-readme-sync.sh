#!/usr/bin/env bash
#
# check-readme-sync.sh — keeps the two READMEs in sync.
#
# The English and the Chinese README carry the same numbers: the size of the
# suite, the size of the adversarial suite, and the number of packages. A
# number that drifts in one file only is a lie in the documentation.
#
# The check compares the two files with each other, and with the result of
# the test suite. It is meant to run in CI: a pull request that adds a test
# without updating the READMEs fails here.
#
# Usage:
#   scripts/check-readme-sync.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ENGLISH="README.md"
CHINESE="README.zh-CN.md"

FAILED=0

fail() { echo "  FAIL  $1"; FAILED=1; }
pass() { echo "  PASS  $1"; }

for file in "$ENGLISH" "$CHINESE"; do
  if [[ ! -f "$file" ]]; then
    fail "$file is missing"
    exit 1
  fi
done

# --- The numbers claimed by the READMEs ---

english_packages=$(sed -n 's/.*make test\.unit` | \([0-9]*\) packages.*/\1/p' "$ENGLISH" | head -1)
english_cases=$(sed -n 's/.*make test\.unit` | [0-9]* packages, \([0-9]*\) cases.*/\1/p' "$ENGLISH" | head -1)
english_adversarial=$(sed -n 's/.*make adversarial` | \([0-9]*\) cases.*/\1/p' "$ENGLISH" | head -1)
english_groups=$(sed -n 's/.*make adversarial` | [0-9]* cases in \([0-9]*\) groups.*/\1/p' "$ENGLISH" | head -1)

chinese_packages=$(sed -n 's/.*make test\.unit` | \([0-9]*\) 个包.*/\1/p' "$CHINESE" | head -1)
chinese_cases=$(sed -n 's/.*make test\.unit` | [0-9]* 个包,\([0-9]*\) 个用例.*/\1/p' "$CHINESE" | head -1)
chinese_adversarial=$(sed -n 's/.*make adversarial` | \([0-9]*\) 个用例.*/\1/p' "$CHINESE" | head -1)
chinese_groups=$(sed -n 's/.*make adversarial` | [0-9]* 个用例 \/ \([0-9]*\) 组.*/\1/p' "$CHINESE" | head -1)

echo "=== The numbers of the two READMEs ==="
echo "  English : ${english_packages:-?} packages, ${english_cases:-?} cases, ${english_adversarial:-?} adversarial, ${english_groups:-?} groups"
echo "  Chinese : ${chinese_packages:-?} packages, ${chinese_cases:-?} cases, ${chinese_adversarial:-?} adversarial, ${chinese_groups:-?} groups"

if [[ -z "$english_cases" || -z "$chinese_cases" ]]; then
  fail "the verification section of a README could not be read"
  exit 1
fi

if [[ "$english_packages" == "$chinese_packages" && "$english_cases" == "$chinese_cases" &&
      "$english_adversarial" == "$chinese_adversarial" && "$english_groups" == "$chinese_groups" ]]; then
  pass "the two READMEs carry the same numbers"
else
  fail "the two READMEs disagree on the numbers of the verification section"
fi

# --- The numbers of the test suite ---

if ! command -v go >/dev/null 2>&1; then
  echo "  SKIP  go is not available, the numbers are not compared with the suite"
  exit $FAILED
fi

real_packages=$(go list ./... 2>/dev/null | wc -l | tr -d ' ')
real_cases=$(go test ./... -count=1 -v 2>/dev/null | grep -cE '^(--- PASS|    --- PASS)')
real_adversarial=$(go test ./internal/adversarial/... -count=1 -v 2>/dev/null | grep -cE '^(--- PASS|    --- PASS)')
real_groups=$(go test ./internal/adversarial/... -count=1 -v 2>/dev/null | grep -cE '^--- PASS')

echo "=== The numbers of the suite ==="
echo "  Actual  : ${real_packages} packages, ${real_cases} cases, ${real_adversarial} adversarial, ${real_groups} groups"

check_number() {
  local label="$1" claimed="$2" real="$3"
  if [[ -z "$claimed" ]]; then
    fail "$label is missing from the README"
    return
  fi
  if [[ "$claimed" == "$real" ]]; then
    pass "$label matches the suite ($real)"
  else
    fail "$label claims $claimed but the suite reports $real"
  fi
}

check_number "the number of packages" "$english_packages" "$real_packages"
check_number "the number of cases" "$english_cases" "$real_cases"
check_number "the number of adversarial cases" "$english_adversarial" "$real_adversarial"
check_number "the number of adversarial groups" "$english_groups" "$real_groups"

echo ""
if [[ "$FAILED" -eq 0 ]]; then
  echo "=== The two READMEs are in sync ==="
else
  echo "=== The two READMEs drifted ==="
fi

exit $FAILED
