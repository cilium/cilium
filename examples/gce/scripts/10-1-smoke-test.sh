#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/guestbook/1-redis-master-controller.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/guestbook/2-redis-master-service.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/guestbook/3-redis-slave-controller.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/guestbook/4-redis-slave-service.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/guestbook/5-guestbook-controller.json
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/gce-example/examples/gce/deployments/guestbook/6-guestbook-service.json

kubectl get pods -o wide

while [[ "$(kubectl get pods | grep guestbook | grep Running -c)" -ne "1" ]] ; do
    echo "Waiting for guestbook pod to be Running..."
    sleep 2s
done

gcloud compute firewall-rules create kubernetes-guestbook-service \
  --allow=tcp:3000 \
  --network kubernetes

worker=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' | grep guestbook | cut -d' ' -f2)

podIP=$(kubectl get pods --output=jsonpath='{range .items[*]}{.metadata.name} {.status.podIP}{"\n"}{end}' | grep guestbook | cut -d' ' -f2)

rm -f 10-2-run-inside-*

echo "sudo apt-get install socat -y && echo 'This terminal needs to be kept open for socat to run' && sudo socat TCP-LISTEN:3000,fork TCP:${podIP}:3000" > "./10-2-run-inside-${worker}.sh"

chmod +x "./10-2-run-inside-${worker}.sh"

gcloud compute copy-files 10-2-run-inside-${worker}.sh ${worker}:~/

echo "Please run ./10-2-run-inside-${worker}.sh inside ${worker}"
