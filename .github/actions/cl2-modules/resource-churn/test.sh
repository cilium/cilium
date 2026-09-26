#!/usr/bin/env bash

# Usage: TEST_SCENARIO=test-scenario ./test.sh

ROOT_DIR=$(realpath ./../../../../)

if [[ ! -f "${ROOT_DIR}/VERSION" ]]; then
    echo "Run from resource-churn cl2 module root."
    exit 1
fi

export EXTRA_KUBEADM_CONFIG_PATCH='
kind: ClusterConfiguration
etcd:
  local:
    extraArgs:
      quota-backend-bytes: "4294967296"
apiServer:
  extraArgs:
    max-requests-inflight: "1200"
    max-mutating-requests-inflight: "600"
    http2-max-streams-per-connection: "1000"
    etcd-compaction-interval: "2m"
controllerManager:
  extraArgs:
    kube-api-qps: "100"
    kube-api-burst: "200"
scheduler:
  extraArgs:
    kube-api-qps: "100"
    kube-api-burst: "200"
'

${ROOT_DIR}/contrib/scripts/kind.sh 1 1
make -C "${ROOT_DIR}" kind-image

