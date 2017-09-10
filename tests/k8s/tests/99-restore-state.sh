#!/usr/bin/env bash
# This tests:

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

manangement_dir="${dir}/../cluster"

# To run the restore functionality, we need to remove cilium ds and re-add it
log "removing Cilium daemonset and readding it"
${manangement_dir}/cluster-manager.bash remove_cilium_ds

wait_for_daemon_set_not_ready kube-system cilium

log "deploying Cilium daemonset"
${manangement_dir}/cluster-manager.bash deploy_cilium

k8s_wait_for_cilium_status_ready kube-system

log "checking that endpoints are restored (number of endpoints is non-zero)"
n_eps=$(k8s_count_all_cluster_cilium_eps kube-system)

if [[ $n_eps -eq "0" ]]; then
    abort "The number of endpoints running should not be zero, restore functionality didn't work as expected"
fi

test_succeeded "${TEST_NAME}"
