#!/bin/bash

# because of https://github.com/kubernetes/kubernetes/issues/60807 , we may end up with garbage terminating
# namespaces leftovers after tests. This is a hacky workaround
kubectl get ns | \
	awk '/Terminating/ {print $1}' | \
   	xargs -n 1 bash -c 'if [ "$#" -ne 1 ]; then exit 0; fi; kubectl get ns -o json $1 | tr -d "\n" | sed "s/\"finalizers\": \[[^]]\+\]/\"finalizers\": []/" | kubectl replace --raw /api/v1/namespaces/$1/finalize -f -' -

# Note: This can be removed once GKE stops having the issue with namespaces no
# deleting.
# because of the hack above, we may end up with orphaned pods etc. We need to
# delete any here. We do this after the hack above to simplify the logic (i.e.
# don't look for the terminating namespaces twice). We also cannot rely on the
# list of terminating namespaces because another run deleted them, leaving
# orphans.
# The commands mimic the DeleteAllInNamespace function in test/helpers/kubectl.go

# Get all namespaces that exist. Terminating ones have been cleared above.
NAMESPACES=$(kubectl get ns -o jsonpath='{range .items[*]}{@.metadata.name}{" "}')

# Get all namespaced types in the k8s system
TYPES=$(kubectl api-resources --namespaced=true --verbs=delete -o name | tr '\n' ',' | sed -e 's/,$//')

# Get all objects of namespaced types
# We use '|' to delimit namespace and type/name since / is already used
OBJECTS=$(kubectl get $TYPES --all-namespaces -o jsonpath="{range .items[*]}{@.metadata.namespace}{'|'}{@.kind}{'/'}{@.metadata.name}{' '}{end}")

# For each object, check if the namespace it is in exists. If the namespace
# does not, delete the object.
for pair in $OBJECTS; do
  IFS='|' read ns obj <<<"$pair"
  #echo "Checking if $ns/$obj ($pair) is present in $NAMESPACES"
  if ! $(echo "$NAMESPACES" | grep -q "$ns" - ) ; then
    echo "Object $obj in $ns is a namespace orphan; deleting"
    kubectl delete -n $ns $obj
  fi
done
