#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

KUBERNETES_HOSTS=(controller0 controller1 controller2)

for host in ${KUBERNETES_HOSTS[*]}; do
  gcloud compute copy-files 04-2-run-inside-vms-kubernetes-controller.sh ${host}:~/
done

echo "The 04-2-run-inside-vms-kubernetes-controller.sh was copied to all controllers"
echo "Please run ./04-2-run-inside-vms-kubernetes-controller.sh inside all 3 controllers, one at a time."
echo "Tip: to ssh the controller, run for example : 'gcloud compute ssh controller0'"
