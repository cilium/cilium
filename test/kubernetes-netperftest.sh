#!/usr/bin/env bash

export PROMETHEUS_URL="$1"
export PROMETHEUS_USR="$2"
export PROMETHEUS_PSW="$3"
export GOPATH="${HOME}/go"
export PS4="==>"
set -x
go get github.com/kubernetes/perf-tests || echo "Nothing to install"

cd ${GOPATH}/src/github.com/kubernetes/perf-tests/network/benchmarks/netperf/
go run launch.go --kubeConfig $HOME/.kube/config

for fp in $(ls -1 ./results_netperf-latest/*.csv);
do
    cat ${fp}
    python3 $GOPATH/src/github.com/cilium/cilium/contrib/scripts/netperf_reporter.py ${fp}
done
