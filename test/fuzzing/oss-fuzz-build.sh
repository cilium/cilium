#/bin/bash -eu

compile_go_fuzzer github.com/cilium/cilium/test/fuzzing Fuzz fuzz gofuzz
