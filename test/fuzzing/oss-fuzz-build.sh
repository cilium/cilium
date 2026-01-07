#!/usr/bin/env bash

set -eu

# The oss-fuzz-build.sh is meant to only be run inside the OSS-Fuzz build environment.
# In that environment, the fuzzers are built with go build which does not include _test.go files
# in its scope and they are therefore renamed.
# When run locally by developers with go test -fuzz then the renaming is not necessary.
# Ciliums OSS-Fuzz integration can be found here: https://github.com/google/oss-fuzz/tree/master/projects/cilium


ln -s "$SRC"/cilium/pkg/policy/distillery_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/l4_filter_deny_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/l4_filter_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/l4_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/mapstate_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/origin_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/repository_deny_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/repository_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/resolve_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/resolve_deny_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/rule_test{,_fuzz}.go
ln -s "$SRC"/cilium/pkg/policy/selectorcache_test{,_fuzz}.go

# Allow Go to download dependencies not present in the vendor directory.
# This is needed for go-118-fuzz-build/testing which is required by compile_native_go_fuzzer.
export GOFLAGS="-mod=mod"

compile_native_go_fuzzer github.com/cilium/cilium/pkg/container/bitlpm FuzzUint8 FuzzUint8
compile_native_go_fuzzer github.com/cilium/cilium/pkg/fqdn/matchpattern FuzzMatchpatternValidate FuzzMatchpatternValidate
compile_native_go_fuzzer github.com/cilium/cilium/pkg/fqdn/matchpattern FuzzMatchpatternValidateWithoutCache FuzzMatchpatternValidateWithoutCache
compile_native_go_fuzzer github.com/cilium/cilium/pkg/fqdn/namemanager FuzzMapSelectorsToNamesLocked FuzzMapSelectorsToNamesLocked
compile_native_go_fuzzer github.com/cilium/cilium/pkg/hubble/parser FuzzParserDecode FuzzParserDecode
compile_native_go_fuzzer github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2 FuzzCiliumClusterwideNetworkPolicyParse FuzzCiliumClusterwideNetworkPolicyParse
compile_native_go_fuzzer github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2 FuzzCiliumNetworkPolicyParse FuzzCiliumNetworkPolicyParse
compile_native_go_fuzzer github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels FuzzLabelsParse FuzzLabelsParse
compile_native_go_fuzzer github.com/cilium/cilium/pkg/labels FuzzNewLabels FuzzNewLabels
compile_native_go_fuzzer github.com/cilium/cilium/pkg/labelsfilter FuzzLabelsfilterPkg FuzzLabelsfilterPkg
compile_native_go_fuzzer github.com/cilium/cilium/pkg/loadbalancer FuzzJSONBackend FuzzJSONBackend
compile_native_go_fuzzer github.com/cilium/cilium/pkg/loadbalancer FuzzJSONFrontend FuzzJSONFrontend
compile_native_go_fuzzer github.com/cilium/cilium/pkg/loadbalancer FuzzJSONService FuzzJSONService
compile_native_go_fuzzer github.com/cilium/cilium/pkg/monitor/format FuzzFormatEvent FuzzFormatEvent
compile_native_go_fuzzer github.com/cilium/cilium/pkg/policy FuzzAccumulateMapChange FuzzAccumulateMapChange
compile_native_go_fuzzer github.com/cilium/cilium/pkg/policy FuzzDenyPreferredInsert FuzzDenyPreferredInsert
compile_native_go_fuzzer github.com/cilium/cilium/pkg/policy FuzzResolvePolicy FuzzResolvePolicy
