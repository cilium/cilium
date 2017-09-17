#!/bin/bash

# Copyright 2017 The Kubernetes Authors.
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

# A configuration for Kubemark cluster. It doesn't need to be kept in
# sync with gce/config-default.sh (except the filename, because I'm reusing
# gce/util.sh script which assumes config filename), but if some things that
# are enabled by default should not run in hollow clusters, they should be disabled here.

source "${KUBE_ROOT}/cluster/gce/config-common.sh"

GCLOUD=gcloud
ZONE=${KUBE_GCE_ZONE:-us-central1-b}
REGION=${ZONE%-*}
NUM_NODES=${KUBEMARK_NUM_NODES:-10}
MASTER_SIZE=${KUBEMARK_MASTER_SIZE:-n1-standard-$(get-master-size)}
MASTER_DISK_TYPE=pd-ssd
MASTER_DISK_SIZE=${MASTER_DISK_SIZE:-20GB}
MASTER_ROOT_DISK_SIZE=${KUBEMARK_MASTER_ROOT_DISK_SIZE:-10GB}
REGISTER_MASTER_KUBELET=${REGISTER_MASTER:-false}
PREEMPTIBLE_NODE=${PREEMPTIBLE_NODE:-false}

MASTER_OS_DISTRIBUTION=${KUBE_MASTER_OS_DISTRIBUTION:-gci}
NODE_OS_DISTRIBUTION=${KUBE_NODE_OS_DISTRIBUTION:-gci}
MASTER_IMAGE=${KUBE_GCE_MASTER_IMAGE:-cos-stable-60-9592-84-0}
MASTER_IMAGE_PROJECT=${KUBE_GCE_MASTER_PROJECT:-cos-cloud}

NETWORK=${KUBE_GCE_NETWORK:-e2e}
INSTANCE_PREFIX="${INSTANCE_PREFIX:-"default"}"
MASTER_NAME="${INSTANCE_PREFIX}-kubemark-master"
AGGREGATOR_MASTER_NAME="${INSTANCE_PREFIX}-kubemark-aggregator"
MASTER_TAG="kubemark-master"
EVENT_STORE_NAME="${INSTANCE_PREFIX}-event-store"
MASTER_IP_RANGE="${MASTER_IP_RANGE:-10.246.0.0/24}"
CLUSTER_IP_RANGE="${CLUSTER_IP_RANGE:-10.224.0.0/11}"
RUNTIME_CONFIG="${KUBE_RUNTIME_CONFIG:-}"
TERMINATED_POD_GC_THRESHOLD=${TERMINATED_POD_GC_THRESHOLD:-100}

# Set etcd image (e.g. 3.0.17-alpha.1) and version (e.g. 3.0.17) if you need
# non-default version.
ETCD_IMAGE="${TEST_ETCD_IMAGE:-}"
ETCD_VERSION="${TEST_ETCD_VERSION:-}"
# Storage backend. 'etcd2' supported, 'etcd3' experimental.
STORAGE_BACKEND=${STORAGE_BACKEND:-}

# Default Log level for all components in test clusters and variables to override it in specific components.
TEST_CLUSTER_LOG_LEVEL="${TEST_CLUSTER_LOG_LEVEL:---v=2}"
KUBELET_TEST_LOG_LEVEL="${KUBELET_TEST_LOG_LEVEL:-$TEST_CLUSTER_LOG_LEVEL}"
API_SERVER_TEST_LOG_LEVEL="${API_SERVER_TEST_LOG_LEVEL:-$TEST_CLUSTER_LOG_LEVEL}"
CONTROLLER_MANAGER_TEST_LOG_LEVEL="${CONTROLLER_MANAGER_TEST_LOG_LEVEL:-$TEST_CLUSTER_LOG_LEVEL}"
SCHEDULER_TEST_LOG_LEVEL="${SCHEDULER_TEST_LOG_LEVEL:-$TEST_CLUSTER_LOG_LEVEL}"
KUBEPROXY_TEST_LOG_LEVEL="${KUBEPROXY_TEST_LOG_LEVEL:-$TEST_CLUSTER_LOG_LEVEL}"

TEST_CLUSTER_DELETE_COLLECTION_WORKERS="${TEST_CLUSTER_DELETE_COLLECTION_WORKERS:---delete-collection-workers=16}"
TEST_CLUSTER_MAX_REQUESTS_INFLIGHT="${TEST_CLUSTER_MAX_REQUESTS_INFLIGHT:-}"
TEST_CLUSTER_RESYNC_PERIOD="${TEST_CLUSTER_RESYNC_PERIOD:-}"

KUBEMARK_MASTER_COMPONENTS_QPS_LIMITS="${KUBEMARK_MASTER_COMPONENTS_QPS_LIMITS:-}"

# ContentType used by all components to communicate with apiserver.
TEST_CLUSTER_API_CONTENT_TYPE="${TEST_CLUSTER_API_CONTENT_TYPE:-}"
# ContentType used to store objects in underlying database.
TEST_CLUSTER_STORAGE_MEDIA_TYPE=""
if [ -n "${STORAGE_MEDIA_TYPE:-}" ]; then
  TEST_CLUSTER_STORAGE_MEDIA_TYPE="--storage-media-type=${STORAGE_MEDIA_TYPE}"
fi

ENABLE_GARBAGE_COLLECTOR=${ENABLE_GARBAGE_COLLECTOR:-true}

CUSTOM_ADMISSION_PLUGINS="${CUSTOM_ADMISSION_PLUGINS:-Initializers,NamespaceLifecycle,LimitRanger,ServiceAccount,PodPreset,DefaultTolerationSeconds,NodeRestriction,ResourceQuota}"

# Master components' test arguments.
APISERVER_TEST_ARGS="${KUBEMARK_APISERVER_TEST_ARGS:-} --runtime-config=extensions/v1beta1 ${API_SERVER_TEST_LOG_LEVEL} ${TEST_CLUSTER_STORAGE_MEDIA_TYPE} ${TEST_CLUSTER_MAX_REQUESTS_INFLIGHT} ${TEST_CLUSTER_DELETE_COLLECTION_WORKERS} --enable-garbage-collector=${ENABLE_GARBAGE_COLLECTOR}"
CONTROLLER_MANAGER_TEST_ARGS="${KUBEMARK_CONTROLLER_MANAGER_TEST_ARGS:-} ${CONTROLLER_MANAGER_TEST_LOG_LEVEL} ${TEST_CLUSTER_RESYNC_PERIOD} ${TEST_CLUSTER_API_CONTENT_TYPE} ${KUBEMARK_MASTER_COMPONENTS_QPS_LIMITS} --enable-garbage-collector=${ENABLE_GARBAGE_COLLECTOR}"
SCHEDULER_TEST_ARGS="${KUBEMARK_SCHEDULER_TEST_ARGS:-} ${SCHEDULER_TEST_LOG_LEVEL} ${TEST_CLUSTER_API_CONTENT_TYPE} ${KUBEMARK_MASTER_COMPONENTS_QPS_LIMITS}"

# Hollow-node components' test arguments.
KUBELET_TEST_ARGS="--max-pods=100 $TEST_CLUSTER_LOG_LEVEL ${TEST_CLUSTER_API_CONTENT_TYPE}"
KUBEPROXY_TEST_ARGS="${KUBEPROXY_TEST_LOG_LEVEL} ${TEST_CLUSTER_API_CONTENT_TYPE}"
USE_REAL_PROXIER=${USE_REAL_PROXIER:-true}  # for hollow-proxy

SERVICE_CLUSTER_IP_RANGE="10.0.0.0/16"  # formerly PORTAL_NET
ALLOCATE_NODE_CIDRS=true

# Optional: Enable cluster autoscaler.
ENABLE_KUBEMARK_CLUSTER_AUTOSCALER="${ENABLE_KUBEMARK_CLUSTER_AUTOSCALER:-false}"
