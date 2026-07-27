#!/usr/bin/env bash

set -eu

# Wrap 'set -x' in checks against DEBUG variable; print input env vars.
DEBUG=${DEBUG:-""}
[ -n "$DEBUG" ] && set -x
FUZZ_TIME=${FUZZ_TIME:-1} # seconds per fuzzer
FUZZ_ARGS=${FUZZ_ARGS:-""}
set +x

FUZZ_BUILD="test/fuzzing/oss-fuzz-build.sh"

# ALL_TESTS is an associative array which maps a package to a lists of fuzzers.
#
# KEY: Go package, example 'pkg/policy'
# VALUE: One or more tests, example 'FuzzMapSelectorsToNamesLocked FuzzBar'
declare -A ALL_TESTS

# find_fuzzers populates 'ALL_TESTS' and 'TEST_COUNT' from oss-fuzz-build.sh.
find_fuzzers() {
    local test_count
    test_count=0

    packages="$(grep compile_native_go_fuzzer "$FUZZ_BUILD" \
                | awk '{ print $2 }' \
                | sed 's/github.com\/cilium\/cilium\///g')"

    while read -r pkg; do
        tests=("$(grep "compile_native_go_fuzzer.*$pkg" "$FUZZ_BUILD" \
                  | awk '{ print $3 }')")

        test_count=$((test_count+${#tests[@]}))
        ALL_TESTS["$pkg"]="${tests[*]}"
    done <<< "$packages"

    >&2 echo "Discovered ${test_count} fuzzers in ${#ALL_TESTS[@]} packages"
}

run_tests() {
    [ -n "$DEBUG" ] && set -x
    for pkg in "${!ALL_TESTS[@]}"; do
        for test in ${ALL_TESTS[${pkg}]}; do
            >&2 echo "Running $test in $pkg..."
            go test "./${pkg}" -fuzz="$test$" -fuzztime="${FUZZ_TIME}"s "${FUZZ_ARGS[@]}"
        done
    done
    set +x
}

main() {
    if [ "$FUZZ_TIME" -le 0 ]; then
        >&2 echo "Timeout $FUZZ_TIME must be >= 0."
        exit 1
    fi

    find_fuzzers
    run_tests
}

main "$@"
