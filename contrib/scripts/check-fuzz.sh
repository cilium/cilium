#!/usr/bin/env bash

set -e
set -o pipefail

FUZZER_BUILD="test/fuzzing/oss-fuzz-build.sh"

fuzz_files="$(grep -Rl 'func Fuzz.*' pkg/)"

result=0
for f in $fuzz_files; do
    if ! [[ "$f" =~ fuzz_test.go$ ]]; then
        >&2 echo "Fuzz function in $f should be in a filename with suffix 'fuzz_test.go'"
        result=1
    fi
done

for f in $fuzz_files; do
    fuzzers="$(grep -R 'func Fuzz.*' "$f" \
               | awk 'match($0, /Fuzz[^(]*/) { print substr($0, RSTART, RLENGTH) }')"
    while read -r fuzzer; do
        if ! grep -q "$fuzzer" "$FUZZER_BUILD" ; then
            if [ $result -eq 0 ]; then
                >&2 echo "Fuzzer(s) missing from $FUZZER_BUILD:"
            fi
            echo "compile_native_go_fuzzer github.com/cilium/cilium/$(dirname "$f") $fuzzer $fuzzer"
	          result=1
        fi
    done <<< "$fuzzers"
done

exit $result

