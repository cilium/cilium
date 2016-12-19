#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

gcloud -q compute instances delete \
  controller0 controller1 controller2 \
  worker0 worker1 worker2

gcloud -q compute forwarding-rules delete --region "${region}" kubernetes-rule

gcloud -q compute target-pools delete kubernetes-pool

gcloud -q compute http-health-checks delete kube-apiserver-check

gcloud -q compute addresses delete kubernetes

gcloud -q compute firewall-rules delete \
  kubernetes-allow-api-server \
  kubernetes-allow-healthz \
  kubernetes-allow-icmp \
  kubernetes-allow-pods \
  kubernetes-guestbook-service \
  kubernetes-allow-internal \
  kubernetes-allow-rdp \
  kubernetes-allow-ssh

gcloud -q compute routes delete $(gcloud -q compute routes list | grep kubernetes-route | cut -d' ' -f 1)

gcloud -q compute networks subnets delete kubernetes

gcloud -q compute networks delete kubernetes
