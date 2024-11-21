#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -e

EXCEPTIONS=(
    "bpf/tests/common.h:12:// clang-format off"
    "bpf/tests/drop_notify_test.c:18:// clang-format off"
)

# Search the bpf/ dir recursively for 'clang-format off' comments and print the line numbers
OUTPUT=$(grep -R -n -E "clang-format +off" bpf/)

# Set IFS to empty to avoid splitting lines with spaces
IFS=""
# Remove all exceptions from the output
for exception in ${EXCEPTIONS[@]}; do
    # Escape slashes in the exception
    exception=$(printf $exception | sed 's/\//\\\//g')
    # Remove the exception from the output
    OUTPUT=$(echo $OUTPUT | sed -z "s/$exception\n//")
done

if [[ $(printf "$OUTPUT" | wc -c) -ne 0 ]]; then
    echo "Found 'clang-format off' comment(s) not part of the exceptions list:"
    echo "$OUTPUT"
    exit 1
fi
