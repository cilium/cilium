#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
. ${dir}/env-kube.sh

ipv6regex='(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

ipv4regex='((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'

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
while [[ -z "$svcIP" && ${i} -le ${tries} ]] ; do
    echo "Getting Guestbook IP. Attempt ${i}/${tries}..."
    if [ -z "${IPV4}" ]; then
        svcIP=$(${kubectl} get svc guestbook | grep -Eo $ipv6regex)
    else
        svcIP=$(${kubectl} get svc guestbook | grep -Eo $ipv4regex)
    fi
    sleep 2
    i=$(( $i + 1 ))
done

if [ ${i} -ge ${tries} ]; then
    echo "Unable to find guestbook IP, please try again in a couple moments"
    exit
fi

echo "Guestbook IP found! Open in your host the address"
if [ -z "${IPV4}" ]; then
    echo "http://[${svcIP}]:3000"
else
    echo "http://${svcIP}:3000"
fi