#!/bin/bash

set -x
set -e

# Uninstall Cilium
cilium uninstall --wait

# Make sure the 'aws-node' DaemonSet blocking nodeSelector was removed
[[ ! $(kubectl -n kube-system get ds/aws-node -o jsonpath="{.spec.template.spec.nodeSelector['io\.cilium/aws-node-enabled']}") ]]
