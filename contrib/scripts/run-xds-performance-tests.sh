#!/usr/bin/env bash

# Run the xDS performance and correctness suite on a single host. The caller is
# responsible for installing Go, cilium-envoy, and cilium-envoy-starter.

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
results_dir=${RESULTS_DIR:-"${repo_root}/xds-performance-results"}
benchmark_time=${XDS_BENCHTIME:-2s}
benchmark_count=${XDS_BENCH_COUNT:-5}
profile_time=${XDS_PROFILE_BENCHTIME:-1s}

mkdir -p "${results_dir}"
results_dir=$(cd "${results_dir}" && pwd)

cd "${repo_root}"

{
	echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "commit=$(git rev-parse HEAD)"
	echo "gomaxprocs=${GOMAXPROCS:-unset}"
	echo "benchmark_time=${benchmark_time}"
	echo "benchmark_count=${benchmark_count}"
	echo
	go version
	cilium-envoy --version
	uname -a
	lscpu
	free -h
} | tee "${results_dir}/metadata.txt"

go test ./pkg/envoy \
	-run '^$' \
	-bench '^BenchmarkDeltaServerEndpointUpdate$' \
	-benchmem \
	-benchtime "${benchmark_time}" \
	-count "${benchmark_count}" \
	-timeout 30m \
	| tee "${results_dir}/delta-server-benchmark.txt"

go test ./pkg/envoy/xdsnew \
	-run '^$' \
	-bench '^BenchmarkGenerateSnapshotSparseEndpointUpdate$' \
	-benchmem \
	-benchtime "${benchmark_time}" \
	-count "${benchmark_count}" \
	-timeout 30m \
	| tee "${results_dir}/snapshot-benchmark.txt"

for mode in delta-split delta-ads; do
	go test ./pkg/envoy \
		-run '^$' \
		-bench "^BenchmarkDeltaServerEndpointUpdate$/${mode}/resources=10000/batch=1$" \
		-benchtime "${profile_time}" \
		-count 1 \
		-timeout 30m \
		-cpuprofile "${results_dir}/${mode}.cpu.pprof" \
		-memprofile "${results_dir}/${mode}.mem.pprof" \
		| tee "${results_dir}/${mode}-profile.txt"
done

CILIUM_ENABLE_ENVOY_UNIT_TEST=1 go test ./pkg/envoy \
	-run '^TestEnvoyDeltaResourceScenario$' \
	-count 1 \
	-timeout 10m \
	-v \
	| tee "${results_dir}/delta-resource-scenario.txt"
