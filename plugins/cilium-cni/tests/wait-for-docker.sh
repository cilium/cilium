#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

set -e
if [ -z $1 ]; then
    return "Empty name"
else
    name=$1
fi

if [ -z $2 ]; then
    tries=10
else
    tries=$2
fi

#Wait for container ${name} to be ready
i=1
while [[ -z "$contID" && ${i} -le ${tries} ]] ; do
    echo "Waiting for container ${name}. Attempt ${i}/${tries}..."
    contID=$(docker ps -aq --filter=name="${name}")
    sleep 2
    i=$(( $i + 1 ))
done

if [ ${i} -ge ${tries} ]; then
    echo "Unable to find container ${name}, please try again in a couple moments"
    exit
fi
