#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

DEPS=/opt/toolchains/deps
# Upstream's CMake FetchContent-clones these at configure time; point it at the in-image copies
# (pinned to the same commits in mayhem/Dockerfile) and forbid any download.
FETCH_ARGS=(
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON
  -DFETCHCONTENT_SOURCE_DIR_ZLIB="$DEPS/zlib-1.3.2/src"
  -DFETCHCONTENT_SOURCE_DIR_ZSTD="$DEPS/zstd-1.5.7/src"
  -DFETCHCONTENT_SOURCE_DIR_MSGSL="$DEPS/msgsl-5.0.1/src"
  -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="$DEPS/googletest-1.18.0/src"
)

# SanitizerCoverage for libFuzzer: the base's SANITIZER_FLAGS carries ASan+UBSan only, so the library
# and harness objects get -fsanitize=fuzzer-no-link explicitly (the link adds $LIB_FUZZING_ENGINE).
FUZZ_CFLAGS="-fsanitize=fuzzer-no-link"

# 1) The library (libseal + the C export layer libsealc) with the sanitizers, into build/
#    (gitignored by upstream's `build/`). zlib/zstd are configured from the same flags as
#    subprojects. Release keeps SEAL_DEBUG off, so bad input reaches the real code paths instead of
#    debug-only precondition throws.
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $FUZZ_CFLAGS $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $FUZZ_CFLAGS $DEBUG_FLAGS" \
  -DSEAL_BUILD_SEAL_C=ON -DSEAL_BUILD_STATIC_SEAL_C=ON \
  -DSEAL_BUILD_TESTS=OFF -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_BENCH=OFF \
  -DSEAL_USE_INTEL_HEXL=OFF \
  "${FETCH_ARGS[@]}"
cmake --build build -j"$MAYHEM_JOBS" --target seal sealc

LIBS=(build/lib/libsealc*.a build/lib/libseal-*.a)
[ -e "${LIBS[1]}" ] || LIBS=(build/lib/libsealc*.a build/lib/libseal.a)
INC=(-I"$SRC/native/src" -I"$SRC/build/native/src" -I"$DEPS/msgsl-5.0.1/src/include")
for l in "${LIBS[@]}"; do [ -f "$l" ] || { echo "missing $l" >&2; ls build/lib >&2; exit 1; }; done
# zlib / zstd archives (built as subprojects; may already be folded into libseal).
mapfile -t EXTRA < <(find build -name 'libz*.a' -o -name 'libzstd*.a' | sort)

# 2) Harnesses: libFuzzer binary + run-once standalone reproducer each.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/standalone_main.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/lsan_off.o
HARNESSES=(fuzz_ciphertext_load fuzz_encparams_load fuzz_evaluator fuzz_kswitchkeys_load
           fuzz_plaintext_load fuzz_decryptor fuzz_c_load
           fuzz_key_load fuzz_plaintext_string fuzz_encoder)
for h in "${HARNESSES[@]}"; do
  $CXX -std=c++17 $SANITIZER_FLAGS $FUZZ_CFLAGS $DEBUG_FLAGS -O1 "${INC[@]}" -c "mayhem/harnesses/$h.cpp" -o "build/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/$h.o" build/lsan_off.o \
    "${LIBS[@]}" "${EXTRA[@]}" -lpthread -lm -o "/mayhem/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "build/$h.o" build/standalone_main.o build/lsan_off.o \
    "${LIBS[@]}" "${EXTRA[@]}" -lpthread -lm -o "/mayhem/$h-standalone"
done

# 3) Upstream's gtest suites with the project's NORMAL flags, in their own tree build-tests/
#    (gitignored by upstream's `build-*/`): sealtest (the C++ library) and sealctest (the C export
#    layer libsealc, which fuzz_c_load fuzzes), as upstream's pipelines/linux.yml builds and runs
#    them. test.sh only runs them.
cmake -S . -B build-tests -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DSEAL_BUILD_TESTS=ON -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_BENCH=OFF -DSEAL_BUILD_SEAL_C=ON \
  -DSEAL_USE_INTEL_HEXL=OFF \
  "${FETCH_ARGS[@]}"
cmake --build build-tests -j"$MAYHEM_JOBS" --target sealtest sealctest
test -x build-tests/bin/sealtest
test -x build-tests/bin/sealctest
