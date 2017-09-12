#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

K8S_TESTS_DIR="/home/vagrant/go/src/github.com/cilium/cilium/tests/k8s/tests"
K8S_TEST_CILIUM_FILES="${K8S_TESTS_DIR}/cilium-files/${K8S}"
IPV4_TESTS_DIR="${K8S_TESTS_DIR}/ipv4"
IPV6_TESTS_DIR="${K8S_TESTS_DIR}/ipv6"

set -ex

function run_tests {
  check_num_params "$#" "1"
  TEST_DIR=$1
  
  log "beginning running tests in directory ${TEST_DIR}"
  for test in ${TEST_DIR}/*.sh ; do 
    file=$(basename $test)
    filename="${file%.*}"
    mkdir -p ${K8S_TEST_CILIUM_FILES}/$filename
    log "running test $test with k8s_version=${k8s_version}"
    $k8s_version=${k8s_version} $test | tee "${K8S_TEST_CILIUM_FILES}/${filename}"/output.txt
  done
  log "done running tests in directory ${TEST_DIR}"
}
