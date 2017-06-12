#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

if [ -z $1 ]; then
	echo "Empty name"
	exit 1
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
while [[ -z "${isRunning}" && ${i} -le ${tries} ]] ; do
	echo "Waiting for pod ${name}. Attempt ${i}/${tries}..."
	isRunning=$(kubectl get pods | grep "${name}" | grep -o "Running")
	i=$(( $i + 1 ))
done

if [ ${i} -ge ${tries} ]; then
	echo "Unable to find pod ${name}, please try again in a moment"
	exit 1
fi
