#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Combine given secrets (in JSON) into one
set -e

if [ "$#" -lt 1 ]
then
    echo "usage: $0 <secret.json>..."
    exit 1
fi

DATA=""
for file in "$@"
do
    DATA+=$(jq -r '.data | to_entries[] | "\"\(.key)\": \"\(.value)\","' $file)
done

# Remove last comma (smallest suffix matching comma) to make data valid json
DATA=${DATA%,}

NAMESPACE=$(kubectl get pod -l k8s-app=clustermesh-apiserver -o jsonpath='{.items[0].metadata.namespace}' --all-namespaces)

cat << EOF |
{
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {
        "name": "cilium-clustermesh"
    },
    "type": "Opaque",
    "data": {
        $DATA
    }
}
EOF
kubectl -n $NAMESPACE apply -f -
