#!/usr/bin/env bash

set -ex

function reinstall_ipv6(){
    vm="${1}"
    vagrant ssh ${vm} -- -t '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/cluster/cluster-manager.bash reinstall --ipv6 --yes-delete-all-etcd-data'
    vagrant ssh ${vm} -- -t 'sudo cp -R /root/.kube /home/vagrant'
    vagrant ssh ${vm} -- -t 'sudo chown vagrant.vagrant -R /home/vagrant/.kube'
}

function deploy_cilium(){
    vagrant ssh cilium-k8s-node-2 -- -t '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/cluster/cluster-manager.bash deploy_cilium'
}

function deploy_cilium_lb(){
    vagrant ssh cilium-k8s-node-2 -- -t '/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/cluster/cluster-manager.bash deploy_cilium --lb-mode'
}

echo "================== Running in IPv4 mode =================="

# Set up cilium-lb-ds and cilium-ds
deploy_cilium

# Run non IP version specific tests
vagrant ssh cilium-k8s-node-2 -- -t 'for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/tests/*.sh; do $test; done'
# Run ipv4 tests
vagrant ssh cilium-k8s-node-2 -- -t 'for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/tests/ipv4/*.sh; do $test; done'

# Reinstall everything with IPv6 addresses
# Kubeadm doesn't quite support IPv6 yet
#reinstall_ipv6 cilium-k8s-master
#reinstall_ipv6 cilium-k8s-node-2

echo "================== Running in IPv6 mode =================="

echo "IPv6 tests are currently disabled"
# Set up cilium-lb-ds and cilium-ds
#deploy_cilium

# Run non IP version specific tests
#vagrant ssh cilium-k8s-node-2 -- -t 'for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/tests/*.sh; do $test; done'
# Run ipv6 tests
#vagrant ssh cilium-k8s-node-2 -- -t 'for test in /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/multi-node/tests/ipv6/*.sh; do $test; done'
