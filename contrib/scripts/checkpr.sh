#!/usr/bin/env bash

set -e

if ! which curl >/dev/null || ! which jq >/dev/null; then
    echo "This tool requires 'curl' and 'jq' utilities to work correctly. Please install them."
    exit 1
fi

if [ $# -eq 0  ]
then
	echo "Usage: checkpr.sh PULL_REQUEST_ID"
	exit
fi

PR_ID=$1

statuses=$(curl -s https://api.github.com/repos/cilium/cilium/pulls/${PR_ID} | jq -r '._links.statuses.href')
jenkins_urls=($(curl -s $statuses | jq -r '.[] | select(.target_url != null) | select(.target_url | contains("jenkins")) | .target_url' | sort | uniq))

for base_url in "${jenkins_urls[@]}"; do
	result="null"
	first=true
	until [ "$result" != "null" ]; do
		if [ $first = true ]; then
			first=false
		else
			sleep 60
		fi
		result=$(curl -s ${base_url}/api/json | jq ".result")
	done
	echo "PR $PR_ID result: $result"
	echo "See $base_url for more details."
done

BARK_PATH="${BARK_PATH:-/usr/share/sounds/freedesktop/stereo/bell.oga}"

name=$(uname)
for run in {1..5}
do
	if [ "$name" == "Linux" ]; then
		paplay ${BARK_PATH}
	else
		# for osx
		afplay /System/Library/Sounds/Ping.aiff
	fi
done
