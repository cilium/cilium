#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

KUBERNETES_HOSTS=(worker0 worker1 worker2)

for host in ${KUBERNETES_HOSTS[*]}; do
  gcloud compute copy-files helpers.bash 05-2-run-inside-vms-kubernetes-worker.sh ${host}:~/
done

echo "The 05-2-run-inside-vms-kubernetes-worker.sh was copied to all workers"
echo "Please run ./05-2-run-inside-vms-kubernetes-worker.sh inside all 3 workers, one at a time."
echo "Tip: to ssh the worker, run for example : 'gcloud compute ssh worker0'"
