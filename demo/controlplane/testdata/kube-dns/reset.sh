#!/bin/sh
kubectl get -n kube-system svc/kube-dns ep/kube-dns -o yaml > input.yaml
