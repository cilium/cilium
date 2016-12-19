#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

gcloud config set compute/region ${region}

gcloud config set compute/zone ${zone}

if [ ! -z "$(gcloud config get-value project 2>&1 | grep '(unset)')" ]; then
    echo "You don't have a project defined in your gcloud config, please set one up with 'gcloud init'"
    exit 0
fi

gcloud compute networks create kubernetes --mode custom

gcloud compute networks subnets create kubernetes \
  --network kubernetes \
  --range ${k8s_cluster_range}

gcloud compute firewall-rules create kubernetes-allow-icmp \
  --allow icmp \
  --network kubernetes \
  --source-ranges 0.0.0.0/0

gcloud compute firewall-rules create kubernetes-allow-internal \
  --allow tcp:0-65535,udp:0-65535,icmp \
  --network kubernetes \
  --source-ranges ${k8s_cluster_range}

gcloud compute firewall-rules create kubernetes-allow-pods \
  --allow tcp:0-65535,udp:0-65535,icmp \
  --network kubernetes \
  --source-ranges ${k8s_cluster_cidr}

gcloud compute firewall-rules create kubernetes-allow-rdp \
  --allow tcp:3389 \
  --network kubernetes \
  --source-ranges 0.0.0.0/0

gcloud compute firewall-rules create kubernetes-allow-ssh \
  --allow tcp:22 \
  --network kubernetes \
  --source-ranges 0.0.0.0/0

gcloud compute firewall-rules create kubernetes-allow-healthz \
  --allow tcp:8080 \
  --network kubernetes \
  --source-ranges 130.211.0.0/22

gcloud compute firewall-rules create kubernetes-allow-api-server \
  --allow tcp:6443 \
  --network kubernetes \
  --source-ranges 0.0.0.0/0

echo "Output of the next command should be similar to"
echo "NAME                         NETWORK     SRC_RANGES      RULES                         SRC_TAGS  TARGET_TAGS
kubernetes-allow-api-server  kubernetes  0.0.0.0/0       tcp:6443
kubernetes-allow-healthz     kubernetes  130.211.0.0/22  tcp:8080
kubernetes-allow-icmp        kubernetes  0.0.0.0/0       icmp
kubernetes-allow-internal    kubernetes  ${k8s_cluster_range}   tcp:0-65535,udp:0-65535,icmp
kubernetes-allow-pods        kubernetes  ${k8s_cluster_cidr}   tcp:0-65535,udp:0-65535,icmp
kubernetes-allow-rdp         kubernetes  0.0.0.0/0       tcp:3389
kubernetes-allow-ssh         kubernetes  0.0.0.0/0       tcp:22"

gcloud compute firewall-rules list --filter "network=kubernetes"

gcloud compute addresses create kubernetes --region=${region}

echo "Output of the next command should be similar to"
echo "NAME        REGION       ADDRESS          STATUS
kubernetes  ${region}  XXX.XXX.XXX.XXX  RESERVED"

gcloud compute addresses list kubernetes

gcloud compute instances create controller0 \
 --boot-disk-size 200GB \
 --can-ip-forward \
 --image ubuntu-1610-yakkety-v20170103 \
 --image-project ubuntu-os-cloud \
 --machine-type n1-standard-1 \
 --private-network-ip ${controllers_ips[0]} \
 --subnet kubernetes

gcloud compute instances create controller1 \
 --boot-disk-size 200GB \
 --can-ip-forward \
 --image ubuntu-1610-yakkety-v20170103 \
 --image-project ubuntu-os-cloud \
 --machine-type n1-standard-1 \
 --private-network-ip ${controllers_ips[1]} \
 --subnet kubernetes

gcloud compute instances create controller2 \
 --boot-disk-size 200GB \
 --can-ip-forward \
 --image ubuntu-1610-yakkety-v20170103 \
 --image-project ubuntu-os-cloud \
 --machine-type n1-standard-1 \
 --private-network-ip ${controllers_ips[2]} \
 --subnet kubernetes

gcloud compute instances create worker0 \
 --boot-disk-size 200GB \
 --can-ip-forward \
 --image ubuntu-1610-yakkety-v20170103 \
 --image-project ubuntu-os-cloud \
 --machine-type n1-standard-1 \
 --private-network-ip ${workers_ips[0]} \
 --subnet kubernetes

gcloud compute instances create worker1 \
 --boot-disk-size 200GB \
 --can-ip-forward \
 --image ubuntu-1610-yakkety-v20170103 \
 --image-project ubuntu-os-cloud \
 --machine-type n1-standard-1 \
 --private-network-ip ${workers_ips[1]} \
 --subnet kubernetes

gcloud compute instances create worker2 \
 --boot-disk-size 200GB \
 --can-ip-forward \
 --image ubuntu-1610-yakkety-v20170103 \
 --image-project ubuntu-os-cloud \
 --machine-type n1-standard-1 \
 --private-network-ip ${workers_ips[2]} \
 --subnet kubernetes

echo "Output of the next command should be similar to"
echo "NAME         ZONE           MACHINE_TYPE   PREEMPTIBLE  INTERNAL_IP  EXTERNAL_IP      STATUS
controller0  ${zone}  n1-standard-1               ${controllers_ips[0]}  XXX.XXX.XXX.XXX  RUNNING
controller1  ${zone}  n1-standard-1               ${controllers_ips[1]}  XXX.XXX.XXX.XXX  RUNNING
controller2  ${zone}  n1-standard-1               ${controllers_ips[2]}  XXX.XXX.XXX.XXX  RUNNING
worker0      ${zone}  n1-standard-1               ${workers_ips[0]}  XXX.XXX.XXX.XXX  RUNNING
worker1      ${zone}  n1-standard-1               ${workers_ips[1]}  XXX.XXX.XXX.XXX  RUNNING
worker2      ${zone}  n1-standard-1               ${workers_ips[2]}  XXX.XXX.XXX.XXX  RUNNING"

gcloud compute instances list