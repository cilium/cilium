#!/bin/bash

# Copyright 2014 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Script to test cluster/update-storage-objects.sh works as expected.

set -o errexit
set -o nounset
set -o pipefail

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/..
source "${KUBE_ROOT}/hack/lib/init.sh"

# The api version in which objects are currently stored in etcd.
KUBE_OLD_API_VERSION=${KUBE_OLD_API_VERSION:-"v1"}
# The api version in which our etcd objects should be converted to.
# The new api version
KUBE_NEW_API_VERSION=${KUBE_NEW_API_VERSION:-"v1"}

KUBE_OLD_STORAGE_VERSIONS=${KUBE_OLD_STORAGE_VERSIONS:-""}
KUBE_NEW_STORAGE_VERSIONS=${KUBE_NEW_STORAGE_VERSIONS:-""}

STORAGE_BACKEND_ETCD2="etcd2"
STORAGE_BACKEND_ETCD3="etcd3"

KUBE_STORAGE_MEDIA_TYPE_JSON="application/json"
KUBE_STORAGE_MEDIA_TYPE_PROTOBUF="application/vnd.kubernetes.protobuf"

ETCD_HOST=${ETCD_HOST:-127.0.0.1}
ETCD_PORT=${ETCD_PORT:-2379}
ETCD_PREFIX=${ETCD_PREFIX:-randomPrefix}
API_PORT=${API_PORT:-8080}
API_HOST=${API_HOST:-127.0.0.1}
KUBE_API_VERSIONS=""
RUNTIME_CONFIG=""

ETCDCTL=$(which etcdctl)
KUBECTL="${KUBE_OUTPUT_HOSTBIN}/kubectl"
UPDATE_ETCD_OBJECTS_SCRIPT="${KUBE_ROOT}/cluster/update-storage-objects.sh"

function startApiServer() {
  local storage_backend=${1:-"${STORAGE_BACKEND_ETCD2}"}
  local storage_versions=${2:-""}
  local storage_media_type=${3:-""}
  kube::log::status "Starting kube-apiserver with KUBE_API_VERSIONS: ${KUBE_API_VERSIONS}"
  kube::log::status "                           and storage-backend: ${storage_backend}"
  kube::log::status "                        and storage-media-type: ${storage_media_type}"
  kube::log::status "                            and runtime-config: ${RUNTIME_CONFIG}"
  kube::log::status "                 and storage-version overrides: ${storage_versions}"

  KUBE_API_VERSIONS="${KUBE_API_VERSIONS}" \
    "${KUBE_OUTPUT_HOSTBIN}/kube-apiserver" \
    --insecure-bind-address="${API_HOST}" \
    --bind-address="${API_HOST}" \
    --insecure-port="${API_PORT}" \
    --storage-backend="${storage_backend}" \
    --etcd-servers="http://${ETCD_HOST}:${ETCD_PORT}" \
    --etcd-prefix="/${ETCD_PREFIX}" \
    --runtime-config="${RUNTIME_CONFIG}" \
    --cert-dir="${TMPDIR:-/tmp/}" \
    --service-cluster-ip-range="10.0.0.0/24" \
    --storage-versions="${storage_versions}" \
    --storage-media-type=${storage_media_type} 1>&2 &
  APISERVER_PID=$!

  # url, prefix, wait, times
  kube::util::wait_for_url "http://${API_HOST}:${API_PORT}/healthz" "apiserver: " 1 120
}

function killApiServer() {
  kube::log::status "Killing api server"
  if [[ -n ${APISERVER_PID-} ]]; then
    kill ${APISERVER_PID} 1>&2 2>/dev/null
    wait ${APISERVER_PID} || true
    kube::log::status "api server exited"
  fi
  unset APISERVER_PID
}

function cleanup() {
  killApiServer

  kube::etcd::cleanup

  kube::log::status "Clean up complete"
}

trap cleanup EXIT SIGINT

make -C "${KUBE_ROOT}" WHAT=cmd/kube-apiserver
make -C "${KUBE_ROOT}" WHAT=cluster/images/etcd/attachlease

kube::etcd::start
echo "${ETCD_VERSION}/${STORAGE_BACKEND_ETCD2}" > "${ETCD_DIR}/version.txt"

### BEGIN TEST DEFINITION CUSTOMIZATION ###

# source_file,resource,namespace,name,old_version,new_version
tests=(
examples/persistent-volume-provisioning/rbd/rbd-storage-class.yaml,storageclasses,,slow,v1beta1,v1
)

KUBE_OLD_API_VERSION="networking.k8s.io/v1,storage.k8s.io/v1beta1,extensions/v1beta1"
KUBE_NEW_API_VERSION="networking.k8s.io/v1,storage.k8s.io/v1,extensions/v1beta1"
KUBE_OLD_STORAGE_VERSIONS="storage.k8s.io/v1beta1"
KUBE_NEW_STORAGE_VERSIONS="storage.k8s.io/v1"

### END TEST DEFINITION CUSTOMIZATION ###

#######################################################
# Step 1: Start a server which supports both the old and new api versions,
# but KUBE_OLD_API_VERSION is the latest (storage) version.
# Additionally use KUBE_STORAGE_MEDIA_TYPE_JSON for storage encoding.
#######################################################
KUBE_API_VERSIONS="v1,${KUBE_OLD_API_VERSION},${KUBE_NEW_API_VERSION}"
RUNTIME_CONFIG="api/all=false,api/v1=true,${KUBE_OLD_API_VERSION}=true,${KUBE_NEW_API_VERSION}=true"
startApiServer ${STORAGE_BACKEND_ETCD2} ${KUBE_OLD_STORAGE_VERSIONS} ${KUBE_STORAGE_MEDIA_TYPE_JSON}


# Create object(s)
for test in ${tests[@]}; do
  IFS=',' read -ra test_data <<<"$test"
  source_file=${test_data[0]}

  kube::log::status "Creating ${source_file}"
  ${KUBECTL} create -f "${source_file}"

  # Verify that the storage version is the old version
  resource=${test_data[1]}
  namespace=${test_data[2]}
  name=${test_data[3]}
  old_storage_version=${test_data[4]}

  if [ -n "${namespace}" ]; then
    namespace="${namespace}/"
  fi
  kube::log::status "Verifying ${resource}/${namespace}${name} has storage version ${old_storage_version} in etcd"
  curl -s http://${ETCD_HOST}:${ETCD_PORT}/v2/keys/${ETCD_PREFIX}/${resource}/${namespace}${name} | grep ${old_storage_version}
done

killApiServer


#######################################################
# Step 2: Perform etcd2 -> etcd3 migration.
# We always perform offline migration, so we need to stop etcd.
#######################################################

kube::etcd::stop
TARGET_STORAGE="etcd3" \
  TARGET_VERSION="3.0.17" \
  DATA_DIRECTORY="${ETCD_DIR}" \
  ETCD=$(which etcd) \
  ETCDCTL=$(which etcdctl) \
  ATTACHLEASE="${KUBE_OUTPUT_HOSTBIN}/attachlease" \
  DO_NOT_MOVE_BINARIES="true" \
  ${KUBE_ROOT}/cluster/images/etcd/migrate-if-needed.sh
kube::etcd::start


#######################################################
# Step 3: Start a server which supports both the old and new api versions,
# but KUBE_NEW_API_VERSION is the latest (storage) version.
# Still use KUBE_STORAGE_MEDIA_TYPE_JSON for storage encoding.
#######################################################

KUBE_API_VERSIONS="v1,${KUBE_NEW_API_VERSION},${KUBE_OLD_API_VERSION}"
RUNTIME_CONFIG="api/all=false,api/v1=true,${KUBE_OLD_API_VERSION}=true,${KUBE_NEW_API_VERSION}=true"
startApiServer ${STORAGE_BACKEND_ETCD3} ${KUBE_NEW_STORAGE_VERSIONS} ${KUBE_STORAGE_MEDIA_TYPE_JSON}

# Update etcd objects, so that will now be stored in the new api version.
kube::log::status "Updating storage versions in etcd"
${UPDATE_ETCD_OBJECTS_SCRIPT}

# Verify that the storage version was changed in etcd
for test in ${tests[@]}; do
  IFS=',' read -ra test_data <<<"$test"
  resource=${test_data[1]}
  namespace=${test_data[2]}
  name=${test_data[3]}
  new_storage_version=${test_data[5]}

  if [ -n "${namespace}" ]; then
    namespace="${namespace}/"
  fi
  kube::log::status "Verifying ${resource}/${namespace}${name} has updated storage version ${new_storage_version} in etcd"
  ETCDCTL_API=3 ${ETCDCTL} --endpoints="${ETCD_HOST}:${ETCD_PORT}" get "/${ETCD_PREFIX}/${resource}/${namespace}${name}" | grep ${new_storage_version}
done

killApiServer


#######################################################
# Step 4 : Start a server which supports only the new api version.
# However, change storage encoding to KUBE_STORAGE_MEDIA_TYPE_PROTOBUF.
#######################################################

KUBE_API_VERSIONS="v1,${KUBE_NEW_API_VERSION}"
RUNTIME_CONFIG="api/all=false,api/v1=true,${KUBE_NEW_API_VERSION}=true"

# This seems to reduce flakiness.
sleep 1
startApiServer ${STORAGE_BACKEND_ETCD3} ${KUBE_NEW_STORAGE_VERSIONS} ${KUBE_STORAGE_MEDIA_TYPE_PROTOBUF}

for test in ${tests[@]}; do
  IFS=',' read -ra test_data <<<"$test"
  resource=${test_data[1]}
  namespace=${test_data[2]}
  name=${test_data[3]}
  namespace_flag=""

  # Verify that the server is able to read the object.
  if [ -n "${namespace}" ]; then
    namespace_flag="--namespace=${namespace}"
    namespace="${namespace}/"
  fi
  kube::log::status "Verifying we can retrieve ${resource}/${namespace}${name} via kubectl"
  # We have to remove the cached discovery information about the old version; otherwise,
  # the 'kubectl get' will use that and fail to find the resource.
  rm -rf ${HOME}/.kube/cache/discovery/localhost_8080/${KUBE_OLD_STORAGE_VERSIONS}
  ${KUBECTL} get ${namespace_flag} ${resource}/${name}
done

killApiServer
