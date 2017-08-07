#!/usr/bin/env bash

# This tests:

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

manangement_dir="${dir}/../cluster"

# To run the restore functionality, we need to remove cilium ds and re-add it
${manangement_dir}/cluster-manager.bash remove_cilium_ds

wait_for_daemon_set_not_ready kube-system cilium

${manangement_dir}/cluster-manager.bash deploy_cilium

k8s_wait_for_cilium_status_ready kube-system

n_eps=$(k8s_count_all_cluster_cilium_eps kube-system)

if [[ $n_eps -eq "0" ]]; then
    abort "The number of endpoints running should not be zero, restore functionality didn't work as expected"
fi
