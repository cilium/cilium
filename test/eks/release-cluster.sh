#!/usr/bin/env bash

set -e

region=eu-central-1
export KUBECONFIG=eks-kubeconfig

cluster=$(cat cluster-name)
ng=$(eksctl get nodegroup --cluster $cluster -r $region -o json | jq -r '.[0].Name')

echo "scaling $cluster ng $ng to 0"
eksctl scale nodegroup -r $region --cluster $cluster -n $ng -N 0

echo "releasing cluster lock from $cluster"
kubectl annotate deployment lock lock-

rm -f cluster-name registry-adder.yaml
