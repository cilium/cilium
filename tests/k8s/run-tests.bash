#!/usr/bin/env bash

set -ex

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

builder=$(get_k8s_vm_name builder)
node1=$(get_k8s_vm_name k8s1)
node2=$(get_k8s_vm_name k8s2)

function vmssh(){
    k8s_version="${k8s_version}" vagrant ssh ${1} -- -o SendEnv=k8s_version -t ${2}
}

# reinstall_kubeadmn re-installs kubeadm in the given VM without clearing up
# etcd
function reinstall_kubeadmn(){
    vm="${1}"
    k8s_version="${2}"
    vmssh ${vm} '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash reinstall --yes-delete-all-data --reinstall-kubeadm'
    vmssh ${vm} 'sudo cp -R /root/.kube /home/vagrant'
    vmssh ${vm} 'sudo chown vagrant.vagrant -R /home/vagrant/.kube'
}

function reinstall_ipv4(){
    vm="${1}"
    k8s_version="${2}"
    vmssh ${vm} '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash reinstall --yes-delete-all-data'
    vmssh ${vm} 'sudo cp -R /root/.kube /home/vagrant'
    vmssh ${vm} 'sudo chown vagrant.vagrant -R /home/vagrant/.kube'
}

function reinstall_ipv6(){
    vm="${1}"
    k8s_version="${2}"
    vmssh ${vm} '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash reinstall --ipv6 --yes-delete-all-data'
    vmssh ${vm} 'sudo cp -R /root/.kube /home/vagrant'
    vmssh ${vm} 'sudo chown vagrant.vagrant -R /home/vagrant/.kube'
}

function deploy_cilium(){
    k8s_version="${1}"
    vmssh ${node2} '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash deploy_cilium'
}

function deploy_cilium_lb(){
    k8s_version="${1}"
    vmssh ${node2} '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/cluster/cluster-manager.bash deploy_cilium --lb-mode'
}

function run_tests(){
    k8s_version="${1}"
    echo "====================== K8S VERSION ======================"
    echo "Node 1"
    vagrant ssh ${node1} -- -t 'kubectl version'
    echo "Node 2"
    vagrant ssh ${node2} -- -t 'kubectl version'

    echo "================== Running in IPv4 mode =================="

    reinstall_ipv4 ${node1} ${k8s_version}
    reinstall_ipv4 ${node2} ${k8s_version}
    # Set up cilium-lb-ds and cilium-ds
    deploy_cilium ${k8s_version}


    # Run non IP version specific tests
    vmssh ${node2} 'set -e; set -o pipefail; for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/*.sh; do file=$(basename $test); filename="${file%.*}"; mkdir -p /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/cilium-files/$filename;  $test | tee /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/cilium-files/"${filename}"/output.txt; done'
    # Run ipv4 tests
    vmssh ${node2} 'set -e; set -o pipefail; for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/ipv4/*.sh; do file=$(basename $test); filename="${file%.*}"; mkdir -p /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/cilium-files/$filename; $test | tee /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/cilium-files/"${filename}"/output.txt; done'

    # Check for deadlocks on node1 cilium pods
    vmssh ${node1} 'set -e; set -o pipefail; for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/999*.sh; do file=$(basename $test); filename="${file%.*}"; mkdir -p /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/cilium-files/$filename;  $test | tee /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/cilium-files/"${filename}"/output.txt; done'
    # Run IPv6 tests

    # Reinstall everything with IPv6 addresses
    # FIXME Kubeadm doesn't quite support IPv6 yet
    #reinstall_ipv6 ${node1} ${k8s_version}
    #reinstall_ipv6 ${node2} ${k8s_version}

    echo "================== Running in IPv6 mode =================="

    echo "IPv6 tests are currently disabled"
    # Run the GSG first and then restart the cluster to run the remaining tests
    #vmssh ${node1} 'set -e; /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/00-gsg-test.bash'
    #
    # Set up cilium-lb-ds and cilium-ds
    #deploy_cilium ${k8s_version}

    # Run non IP version specific tests
    #vmssh ${node2} 'set -e; for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/*.sh; do $test; done'
    # Run ipv6 tests
    #vmssh ${node2} 'set -e; for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/ipv6/*.sh; do $test; done'
}

# Docker registry not needed after provisioning.
vagrant destroy -f ${builder} || echo "Nothing to destroy"

# Run tests in k8s 1.6.6 (which is installed by default in Vagrantfile)
run_tests "1.6.6-00"
# Run tests in k8s 1.7.4 (where we need to reinstall it)
reinstall_kubeadmn ${node1} "1.7.4-00"
reinstall_kubeadmn ${node2} "1.7.4-00"
run_tests "1.7.4-00"
