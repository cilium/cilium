#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

compile_go_fuzzer github.com/cilium/cilium/test/fuzzing Fuzz fuzz gofuzz
