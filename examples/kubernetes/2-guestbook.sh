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

#Create Guestbook
set +e
${kubectl} create -f ${dir}/guestbook
set -e

#Wait for guestbook to be ready and have an IP
i=1
while [[ -z "$podIP" && ${i} -le ${tries} ]] ; do
    echo "Getting Guestbook IP. Attempt ${i}/${tries}..."
    dockerID=$(${kubectl} describe pods guestbook | grep 'Container ID' | grep -oE '[0-9a-f]{64}' | head -1)
    podIP=$(getIPv6 $dockerID)
    sleep 2
    i=$(( $i + 1 ))
done

if [ ${i} -ge ${tries} ]; then
    echo "Unable to find guestbook IP, please try again in a couple moments"
    exit
fi

echo "Guestbook IP found! Open in your host the address"
echo "http://[${podIP}]:3000"
