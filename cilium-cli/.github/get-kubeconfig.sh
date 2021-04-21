#!/bin/bash

# Copyright 2020 Gravitational, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# original script was downloaded from
# https://github.com/gravitational/teleport/blob/master/examples/k8s-auth/get-kubeconfig.sh

# This script creates a new k8s Service Account and generates a kubeconfig with
# its credentials. This Service Account is a cluster admin
# Teleport. The kubeconfig is written in the current directory.
#
# You can override the default namespace "teleport" using the
# NAMESPACE_NAME environment variable.
# You can override the default service account name "teleport-sa" using the
# SA_NAME environment variable.

set -eu -o pipefail

# Allow passing in common name and username in environment. If not provided,
# use default.
SA=${SA_NAME:-kubectl}
NAMESPACE=${NAMESPACE_NAME:-kube-system}

# Set OS specific values.
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    BASE64_DECODE_FLAG="-d"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    BASE64_DECODE_FLAG="-D"
elif [[ "$OSTYPE" == "linux-musl" ]]; then
    BASE64_DECODE_FLAG="-d"
else
    echo "Unknown OS ${OSTYPE}"
    exit 1
fi

echo "Creating the Kubernetes Service Account with minimal RBAC permissions."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${SA}
  namespace: ${NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubectl-test-crb
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: ""
subjects:
- kind: ServiceAccount
  name: ${SA}
  namespace: ${NAMESPACE}
EOF
# Get the service account token and CA cert.
SA_SECRET_NAME=$(kubectl get -n "${NAMESPACE}" sa/"${SA}" -o "jsonpath={.secrets[0]..name}")
# Note: service account token is stored base64-encoded in the secret but must
# be plaintext in kubeconfig.
SA_TOKEN=$(kubectl get -n "${NAMESPACE}" secrets/"${SA_SECRET_NAME}" -o "jsonpath={.data['token']}" | base64 ${BASE64_DECODE_FLAG})
CA_CERT=$(kubectl get -n "${NAMESPACE}" secrets/"${SA_SECRET_NAME}" -o "jsonpath={.data['ca\.crt']}")

# Extract cluster IP from the current context
CURRENT_CONTEXT=$(kubectl config current-context)
CURRENT_CLUSTER=$(kubectl config view -o jsonpath="{.contexts[?(@.name == \"${CURRENT_CONTEXT}\"})].context.cluster}")
CURRENT_CLUSTER_ADDR=$(kubectl config view -o jsonpath="{.clusters[?(@.name == \"${CURRENT_CLUSTER}\"})].cluster.server}")

echo "Writing kubeconfig."
cat > kubeconfig <<EOF
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: ${CA_CERT}
    server: ${CURRENT_CLUSTER_ADDR}
  name: ${CURRENT_CLUSTER}
contexts:
- context:
    cluster: ${CURRENT_CLUSTER}
    user: ${SA}
  name: ${CURRENT_CONTEXT}
current-context: ${CURRENT_CONTEXT}
kind: Config
preferences: {}
users:
- name: ${SA}
  user:
    token: ${SA_TOKEN}
EOF

echo "---
Done!

Copy the generated kubeconfig file to your Teleport Proxy server, and set the
kubeconfig_file parameter in your teleport.yaml config file to point to this
kubeconfig file.

Note: Kubernetes RBAC rules for Teleport were created, you won't need to create them manually."
