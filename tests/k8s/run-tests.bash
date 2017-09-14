#!/usr/bin/env bash

set -ex
set +x

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

node1=$(get_k8s_vm_name k8s1 ${k8s_version})
node2=$(get_k8s_vm_name k8s2 ${k8s_version})

K8S_TESTS_DIR="/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests"
K8S_TEST_CILIUM_FILES="${K8S_TESTS_DIR}/cilium-files/${K8S}"
IPV4_TESTS_DIR="${K8S_TESTS_DIR}/ipv4"
IPV6_TESTS_DIR="${K8S_TESTS_DIR}/ipv6"

function vmssh(){
  log "running command: ${2} on VM: ${1}"
  K8S="${K8S}" k8s_version="${k8s_version}" vagrant ssh ${1} -- -o SendEnv=k8s_version -t ${2}
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
    log "====================== K8S VERSION ======================"
    log "Node 1"
    K8S=${K8S} vagrant ssh ${node1} -- -t 'kubectl version'
    log "Node 2"
    K8S=${K8S} vagrant ssh ${node2} -- -t 'kubectl version'

    log "================== Running in IPv4 mode =================="

    #reinstall_ipv4 ${node1} ${k8s_version}
    #reinstall_ipv4 ${node2} ${k8s_version}
    # Set up cilium-lb-ds and cilium-ds
    deploy_cilium ${k8s_version}


    # Run non IP version specific tests
    vmssh ${node2} "/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/run-tests-vagrant.bash run_tests /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests"
    # Run ipv4 tests
    vmssh ${node2} "/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/run-tests-vagrant.bash run_tests /home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests/ipv4"

    # Run IPv6 tests

    # Reinstall everything with IPv6 addresses
    # FIXME Kubeadm doesn't quite support IPv6 yet
    #reinstall_ipv6 ${node1} ${k8s_version}
    #reinstall_ipv6 ${node2} ${k8s_version}

    echo "================== Running in IPv6 mode =================="

    echo "IPv6 tests are currently disabled"
    # Run non IP version specific tests
    #vmssh ${node2} "/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/run-tests-vagrant.bash run_tests ${K8S_TESTS_DIR}"
    # Run ipv6 tests
    #vmssh ${node2} "/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/run-tests-vagrant.bash run_tests ${IPV6_TESTS_DIR}"
}

if [ -z "${K8S}" ] ; then
  echo "K8S environment variable not set; please set it and re-run this script"
  exit 1
fi

if [ -z "${UPGRADE}" ] ; then 
  echo "UPGRADE variable not set; not running upgrade tests"
  UPGRADE=0
fi


if [[ "${UPGRADE}" == "0" ]]; then
  case "${K8S}" in
    "1.6")
      run_tests "1.6.6-00"
      ;;
    "1.7")
      run_tests "1.7.4-00"
      ;;
    *)
      echo "Usage: K8S={1.6,1.7} run-tests.sh"
      exit 1
  esac
else 
  case "${K8S}" in
    "1.6")
      # Run tests in k8s 1.6.6 (which is installed by default in Vagrantfile)
      run_tests "1.6.6-00"
      # Run tests in k8s 1.7.4 (where we need to reinstall it)
      reinstall_kubeadmn ${node1} "1.7.4-00"
      reinstall_kubeadmn ${node2} "1.7.4-00"
      run_tests "1.7.4-00"
      ;;
    "1.7")
      echo "Cilium only supports up to K8s version 1.7 right now, so just performing K8S 1.7 tests without upgrading"
      run_tests "1.7.4-00"
      ;;
    *)
      echo "Usage: K8S={1.6,1.7} run-tests.sh"
      exit 1
  esac
fi
