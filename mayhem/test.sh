#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's gtest suites (native/tests), built by mayhem/build.sh into build-tests/bin/: sealtest
# (known-answer encode/encrypt/evaluate/decrypt results and serialization round trips of the C++
# library) and sealctest (the C export layer: exception firewall, output capacity, null inputs,
# bounds), run in that order like upstream's pipelines/linux.yml. Counts are summed into one report.
P=0 F=0 S=0
run_suite() {
  local runner="$SRC/build-tests/bin/$1" log rc total passed skipped failed
  if [ ! -x "$runner" ]; then
    echo "test.sh: $runner missing — mayhem/build.sh should have built it" >&2
    F=$((F + 1))
    return
  fi
  log="$(mktemp)"
  "$runner" --gtest_color=no 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  total=$(sed -n 's/^\[==========\] \([0-9]\+\) tests\? from .* ran\..*/\1/p' "$log" | tail -1)
  passed=$(sed -n 's/^\[  PASSED  \] \([0-9]\+\) tests\?\..*/\1/p' "$log" | tail -1)
  skipped=$(sed -n 's/^\[  SKIPPED \] \([0-9]\+\) tests\?,.*/\1/p' "$log" | tail -1)
  failed=$(sed -n 's/^\[  FAILED  \] \([0-9]\+\) tests\?,.*/\1/p' "$log" | tail -1)
  rm -f "$log"
  : "${passed:=0}" "${skipped:=0}" "${failed:=0}"
  # No gtest summary at all (runner crashed or did nothing), or a non-zero exit without a counted
  # failure, is a failure of the suite.
  if [ -z "$total" ] || [ "$total" -eq 0 ] || { [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; }; then
    failed=$((failed + 1))
  fi
  P=$((P + passed)) F=$((F + failed)) S=$((S + skipped))
}
run_suite sealtest
run_suite sealctest
emit_ctrf "gtest" "$P" "$F" "$S"
