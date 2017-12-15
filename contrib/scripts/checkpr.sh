#!/usr/bin/env bash

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

result="null"

until [ "$result" != "null" ]; do
	sleep 60
	result=$(curl -s https://jenkins.cilium.io/job/cilium/job/cilium/job/PR-${PR_ID}/lastBuild/api/json | jq ".result")
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
