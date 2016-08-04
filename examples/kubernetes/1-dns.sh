#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

. ${dir}/env-kube.sh

. ${dir}/utils.sh

set -e

if [ -z $1 ]; then
    tries=10
else
    tries=$1
fi

kubectl="/home/vagrant/kubernetes/cluster/kubectl.sh -s ${API_HOST}:${API_PORT}"
export RESOLV_FILE="/home/vagrant/resolv.conf"

#Create SkyDNS
envsubst \$API_HOST_IP,\$ETCD_HOST < ${dir}/skydns/skydns-rc.yaml.in > ${dir}/skydns/skydns-rc.yaml
envsubst \$RESOLV_FILE < ${dir}/guestbook/1-redis-master-controller.json.in > ${dir}/guestbook/1-redis-master-controller.json
envsubst \$RESOLV_FILE < ${dir}/guestbook/3-redis-slave-controller.json.in > ${dir}/guestbook/3-redis-slave-controller.json
envsubst \$RESOLV_FILE < ${dir}/guestbook/5-guestbook-controller.json.in > ${dir}/guestbook/5-guestbook-controller.json
set +e
${kubectl} create -f ${dir}/skydns
set -e

#Wait for SkyDNS to be ready and have an IP
i=1
while [[ -z "$podIP" && ${i} -le ${tries} ]] ; do
    echo "Getting DNS IP. Attempt ${i}/${tries}..."
    dockerID=$(${kubectl} describe pods --namespace=kube-system kube-dns-v11 | grep 'Container ID' | grep -oE '[0-9a-f]{64}' | head -1)
    podIP=$(getIPv6 $dockerID)
    sleep 2s
    i=$(( $i + 1 ))
done

if [ ${i} -gt ${tries} ]; then
    echo "Unable to find DNS IP, please try again in a couple moments"
    exit
fi

echo "DNS IP found: ${podIP}"

sudo -E bash <<EOF
echo -e "search default.svc.${DNS_DOMAIN} svc.${DNS_DOMAIN} ${DNS_DOMAIN}\n\
nameserver ${podIP}\n\
options ndots:5" > "${RESOLV_FILE}"
EOF
