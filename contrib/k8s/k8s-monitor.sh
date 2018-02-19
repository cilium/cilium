#!/bin/bash

trap 'kill $(jobs -p)' EXIT

while read -r p; do
	kubectl -n kube-system exec -ti $p -- cilium monitor $*&
done <<< "$(kubectl -n kube-system get pods -l k8s-app=cilium | awk '{print $1}' | grep cilium)"

wait
