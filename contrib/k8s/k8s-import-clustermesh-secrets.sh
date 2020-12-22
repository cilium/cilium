#!/bin/bash
#
# Copyright 2020 Authors of Cilium
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
