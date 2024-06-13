#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=grpc-ecosystem/grpc-health-probe
grpc_health_probe_version="v0.4.27"

declare -A grpc_health_probe_sha256
# renovate: datasource=github-release-attachments depName=grpc-ecosystem/grpc-health-probe digestVersion=v0.4.27
grpc_health_probe_sha256[amd64]="7e7687f9cc16fb9f8d6a6e24c8a0809ecd673c0cf42a4f909ef028de06dd84ad"
# renovate: datasource=github-release-attachments depName=grpc-ecosystem/grpc-health-probe digestVersion=v0.4.27
grpc_health_probe_sha256[arm64]="fcc40532d4b169e7f7ca1e8a058eb80b6f97f28d6a60be34e28ac72dc71a23f5"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${grpc_health_probe_version}/grpc_health_probe-linux-${arch}" --output "/tmp/grpc_health_probe-${arch}"
  printf "%s %s" "${grpc_health_probe_sha256[${arch}]}" "/tmp/grpc_health_probe-${arch}" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  cp /tmp/grpc_health_probe-${arch} /out/linux/${arch}/bin/grpc_health_probe
  chmod +x /out/linux/${arch}/bin/grpc_health_probe
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/grpc_health_probe
aarch64-linux-gnu-strip /out/linux/arm64/bin/grpc_health_probe
