#!/usr/bin/env bash
set -e

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

cd "${dir}"

if [ -z "${K8S}" ] ; then
  echo "K8S environment variable not set; please set it and re-run this script"
  exit 1
fi

case "${K8S}" in 
  "1.6")
    echo "Testing with K8S=1.6"
    K8S=1.6 VAGRANT_DEFAULT_PROVIDER=virtualbox vagrant up --provider=virtualbox
    K8S=1.6 make k8s-multi-node-tests-1.6
    ;;
  "1.7")
    echo "Testing with K8S=1.7"
    K8S=1.7 VAGRANT_DEFAULT_PROVIDER=virtualbox vagrant up --provider=virtualbox
    K8S=1.7 make k8s-multi-node-tests-1.7
    ;;
  *)
    echo "Usage: K8S={1.6,1.7} start.sh"
    exit 1
esac
