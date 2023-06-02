#!/usr/bin/env bash

cd install/kubernetes/cilium/templates
echo "Checking for differences between preflight and agent clusterrole"
diff=$(diff \
 -I '^[ ]\{2\}name: cilium.*' \
 -I '^Keep file in sync with.*' \
 -I '{{- if.*' \
 cilium-agent/clusterrole.yaml \
 cilium-preflight/clusterrole.yaml)

if [ -n "$diff" ]; then
	echo "A diff exists between cilium-agent/clusterrole.yaml and cilium-preflight/clusterrole.yaml"
    echo ""
	echo "$diff"
    echo ""
	echo "Please ensure both files are the same."
	exit 1
fi
echo "cilium-agent/clusterrole.yaml and cilium-preflight/clusterrole.yaml clusterroles are in in sync"
