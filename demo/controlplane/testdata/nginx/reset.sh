#!/bin/sh
kubectl run nginx --image=nginx --expose --port 12345

while :; do
    kubectl get ep/nginx | grep none || break
    sleep 1
done

kubectl get svc/nginx ep/nginx -o yaml > input.yaml
kubectl delete pod/nginx svc/nginx
