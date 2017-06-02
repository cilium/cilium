#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl create -f "${dir}/../network-policy/" || true

kubectl get networkpolicy

# TODO remove sudo once socket permissions are set with cilium group
cat <<EOF | sudo cilium -D policy import -
[{
    "endpointSelector": {"matchLabels":{"k8s-app":"kube-dns"}},
    "ingress": [{
        "from": [
           {
            "namespaceSelector": {
              "matchLabels": {
                "kube-system": ""
              }
            }
          },
             {
            "namespaceSelector": {
              "matchLabels": {
                "default": ""
              }
            }
          },
          {
            "podSelector": {
              "matchLabels": {
                "io.cilium.reserved": "host"
              }
            }
          }
        ]
    }]
}]
EOF

sudo cilium policy get
