#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

##@ API targets
# Set CRD_OPTIONS if not already set
CRD_OPTIONS="${CRD_OPTIONS:-"crd:crdVersions=v1"}"

# Set CRD_PATHS using the current working directory
CRD_PATHS="${SCRIPT_ROOT}/../../pkg/k8s/apis/cilium.io/v2;${SCRIPT_ROOT}/../../pkg/k8s/apis/cilium.io/v2alpha1;"

# Set CRDS_CILIUM_PATHS using the current working directory
CRDS_CILIUM_PATHS="${SCRIPT_ROOT}/../../pkg/k8s/apis/cilium.io/client/crds/v2 ${SCRIPT_ROOT}/../../pkg/k8s/apis/cilium.io/client/crds/v2alpha1"

# Set CRDS_CILIUM_V2 with the list of CRDs for v2
CRDS_CILIUM_V2="ciliumnetworkpolicies \
                ciliumclusterwidenetworkpolicies \
                ciliumendpoints \
                ciliumidentities \
                ciliumnodes \
                ciliumlocalredirectpolicies \
                ciliumegressgatewaypolicies \
                ciliumenvoyconfigs \
                ciliumclusterwideenvoyconfigs \
                ciliumnodeconfigs"

# Set CRDS_CILIUM_V2ALPHA1 with the list of CRDs for v2alpha1
CRDS_CILIUM_V2ALPHA1="ciliumendpointslices \
                      ciliumbgppeeringpolicies \
                      ciliumbgpclusterconfigs \
                      ciliumbgppeerconfigs \
                      ciliumbgpadvertisements \
                      ciliumbgpnodeconfigs \
                      ciliumbgpnodeconfigoverrides \
                      ciliumloadbalancerippools \
                      ciliumcidrgroups \
                      ciliuml2announcementpolicies \
                      ciliumpodippools"

TMPDIR=$(mktemp -d -t cilium.tmpXXXXXXXX)
go run sigs.k8s.io/controller-tools/cmd/controller-gen ${CRD_OPTIONS} paths="${CRD_PATHS}" output:crd:artifacts:config="${TMPDIR}"
go run ${SCRIPT_ROOT}/../../tools/crdcheck "${TMPDIR}"

# Clean up old CRD state and start with a blank state.
for path in ${CRDS_CILIUM_PATHS}; do
  rm -rf "${path}" && mkdir "${path}"
done

for file in ${CRDS_CILIUM_V2}; do
  mv "${TMPDIR}/cilium.io_${file}.yaml" "${SCRIPT_ROOT}/../../pkg/k8s/apis/cilium.io/client/crds/v2/${file}.yaml";
done

for file in ${CRDS_CILIUM_V2ALPHA1}; do
  mv "${TMPDIR}/cilium.io_${file}.yaml" "${SCRIPT_ROOT}/../../pkg/k8s/apis/cilium.io/client/crds/v2alpha1/${file}.yaml";
done

rm -rf "${TMPDIR}"
