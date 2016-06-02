#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

. ${dir}/env-kube.sh

set -e

if [ -z $1 ]; then
    tries=10
else
    tries=$1
fi

set +e
i=1
while [[ ${i} -le ${tries} ]] ; do
    echo "Waiting for kubernetes to start. Attempt ${i}/${tries}..."
    ${kubectl} get nodes
    if [ $? == 0 ]; then
        break
    fi
    sleep 2s
    i=$(( $i + 1 ))
done
if [ ${i} -gt ${tries} ]; then
    echo "Kubernetes didn't start please start again..."
    exit
fi

${kubectl} create -f ${dir}/network-policy/resource.yaml
sleep 15s
set -e

curl -g -X POST -H "Content-Type: application/json" -d @${dir}/network-policy/admin-policy.json \
    http://${API_HOST}:${API_PORT}/apis/experimental.kubernetes.io/v1/namespaces/default/networkpolicys

curl -g -X POST -H "Content-Type: application/json" -d @${dir}/network-policy/lizards-policy.json \
    http://${API_HOST}:${API_PORT}/apis/experimental.kubernetes.io/v1/namespaces/default/networkpolicys
