#!/usr/bin/env bash
set -e
. ./env-kube.sh

kubectl="/home/vagrant/kubernetes/cluster/kubectl.sh"
export RESOLV_FILE="/home/vagrant/resolv.conf"

#Create SkyDNS
envsubst \$NODE_IP < ./skydns/skydns-rc.yaml.in > ./skydns/skydns-rc.yaml
envsubst \$RESOLV_FILE < ./guestbook/1-redis-master-controller.json.in > ./guestbook/1-redis-master-controller.json
envsubst \$RESOLV_FILE < ./guestbook/3-redis-slave-controller.json.in > ./guestbook/3-redis-slave-controller.json
envsubst \$RESOLV_FILE < ./guestbook/5-guestbook-controller.json.in > ./guestbook/5-guestbook-controller.json
set +e
${kubectl} create -f ./skydns
set -e

#Wait for SkyDNS to be ready and have an IP
i=1
while [[ -z "$podIP" && ${i} -lt 10 ]] ; do
    echo "Getting DNS IP. Attempt ${i}/10..."
    podIP=$(${kubectl} describe pods --namespace=kube-system kube-dns-v11 | grep IP | sed -E 's/IP:[[:blank:]]+//g' )
    sleep 2
    i=$(( $i + 1 ))
done

if [ ${i} -ge 10 ]; then
    echo "Unable to find DNS IP, please try again in a couple moments"
    exit
fi

echo "DNS IP found: ${podIP}"

sudo -E bash <<EOF
echo -e "search default.svc.${DNS_DOMAIN} svc.${DNS_DOMAIN} ${DNS_DOMAIN}\n\
nameserver ${podIP}\n\
options ndots:5" > "${RESOLV_FILE}"
EOF
