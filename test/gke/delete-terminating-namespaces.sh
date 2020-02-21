#!/bin/bash

# because of https://github.com/kubernetes/kubernetes/issues/60807 , we may end up with garbage terminating
# namespaces leftovers after tests. This is a hacky workaround
kubectl get ns | grep Terminating | awk '{print $1}' | xargs -n 1 bash -c 'kubectl get ns -o json $1 | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" | kubectl replace --raw /api/v1/namespaces/$1/finalize -f -' -
