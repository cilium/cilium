#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
. ${dir}/env-kube.sh

set -e

if [ -z $1 ]; then
    tries=10
else
    tries=$1
fi

kubectl="/home/vagrant/kubernetes/cluster/kubectl.sh -s ${API_HOST}:${API_PORT}"

#Create Guestbook
set +e
${kubectl} create -f ${dir}/guestbook
set -e

#Wait for guestbook to be ready and have an IP
i=1
while [[ -z "$podIP" && ${i} -le ${tries} ]] ; do
    echo "Getting Guestbook IP. Attempt ${i}/${tries}..."
    podIP=$(${kubectl} describe pods guestbook | grep IP | sed -E 's/IP:[[:blank:]]+//g' )
    sleep 2
    i=$(( $i + 1 ))
done

if [ ${i} -ge ${tries} ]; then
    echo "Unable to find guestbook IP, please try again in a couple moments"
    exit
fi

echo "Guestbook IP found! Open in your host the address"
echo "http://[${podIP}]:3000"
