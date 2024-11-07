#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o xtrace
set -o errexit
set -o pipefail
set -o nounset

# renovate: datasource=github-release-attachments depName=grpc-ecosystem/grpc-health-probe
grpc_health_probe_version="v0.4.35"

declare -A grpc_health_probe_sha256
# renovate: datasource=github-release-attachments depName=grpc-ecosystem/grpc-health-probe digestVersion=v0.4.35
grpc_health_probe_sha256[amd64]="7e98a938983343b00c09a04faf13be0a2cb77fb476410ebca99721598fa2499f"
# renovate: datasource=github-release-attachments depName=grpc-ecosystem/grpc-health-probe digestVersion=v0.4.35
grpc_health_probe_sha256[arm64]="43b381aabf5e1f6b2636558b78dfa169ba5b0edb18b031ebbe71558ac82e8789"

for arch in amd64 arm64 ; do
  curl --fail --show-error --silent --location "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${grpc_health_probe_version}/grpc_health_probe-linux-${arch}" --output "/tmp/grpc_health_probe-${arch}"
  printf "%s %s" "${grpc_health_probe_sha256[${arch}]}" "/tmp/grpc_health_probe-${arch}" | sha256sum -c
  mkdir -p "/out/linux/${arch}/bin"
  cp /tmp/grpc_health_probe-${arch} /out/linux/${arch}/bin/grpc_health_probe
  chmod +x /out/linux/${arch}/bin/grpc_health_probe
done

x86_64-linux-gnu-strip /out/linux/amd64/bin/grpc_health_probe
aarch64-linux-gnu-strip /out/linux/arm64/bin/grpc_health_probe
