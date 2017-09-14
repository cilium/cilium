#!/usr/bin/env bash
set -e

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd "${dir}"

if [ -z "${k8s_version}" ] ; then
  echo "k8s_version environment variable not set; please set it and re-run this script"
  exit 1
fi

case "${k8s_version}" in
  "1.6.6-00")    
    echo "Testing with k8s_version=${k8s_version}"
    k8s_version="${k8s_version}" VAGRANT_DEFAULT_PROVIDER=virtualbox vagrant up --provider=virtualbox
    make k8s-multi-node-tests-1.6
    ;;
  "1.7")
    echo "Testing with k8s_version=${k8s_version}"
    k8s_version="${k8s_version}" VAGRANT_DEFAULT_PROVIDER=virtualbox vagrant up --provider=virtualbox
    make k8s-multi-node-tests-1.7
    ;;
  *)
    "Usage: k8s_version={1.6.6-00,1.7.4-00} start.sh"
    exit 1
esac
