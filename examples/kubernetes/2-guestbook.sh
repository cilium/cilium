#!/usr/bin/env bash
set -e
. ./env-kube.sh

kubectl="/home/vagrant/kubernetes/cluster/kubectl.sh"

#Create Guestbook
set +e
${kubectl} create -f ./guestbook
set -e

#Wait for guestbook to be ready and have an IP
i=1
while [[ -z "$podIP" && ${i} -lt 10 ]] ; do
    echo "Getting Guestbook IP. Attempt ${i}/10..."
    podIP=$(${kubectl} describe pods guestbook | grep IP | sed -E 's/IP:[[:blank:]]+//g' )
    sleep 2
    i=$(( $i + 1 ))
done

if [ ${i} -ge 10 ]; then
    echo "Unable to find guestbook IP, please try again in a couple moments"
    exit
fi

echo "Guestbook IP found! Open in your host the address"
echo "http://[${podIP}]:3000"
