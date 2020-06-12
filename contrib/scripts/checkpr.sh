#!/usr/bin/env bash

set -e

if ! which curl >/dev/null || ! which jq >/dev/null; then
    echo "This tool requires 'curl' and 'jq' utilities to work correctly. Please install them."
    exit 1
fi

usage() {
	echo -e "Usage: checkpr.sh PULL_REQUEST_ID"
	echo -e "Options:"
	echo -e "\t-h\tdisplay this help"
	echo -e "\t-m\tdisable audio notifications"
	echo -e "\t-q\tdisable textual notifications"
}

notif_audio=1
notif_desktop=1
OPTIND=1
while getopts "hmq" opt; do
	case "$opt" in
		h)
			usage
			exit 0
			;;
		m)
			notif_audio=0
			;;
		q)
			notif_desktop=0
			;;
	esac
done
shift $((OPTIND-1))
[[ "${1:-}" = "--" ]] && shift

if [ $# -eq 0  ]
then
	usage
	exit 1
fi

BARK_PATH="${BARK_PATH:-/usr/share/sounds/freedesktop/stereo/bell.oga}"
name=$(uname)
notify() {
	if [ $notif_desktop -eq 1 ]; then
		set +e
		notify-send "$1" "$2"
		set -e
	fi

	if [ $notif_audio -eq 0 ]; then
		return 0
	fi

	for run in {1..5}
	do
		if [ "$name" == "Linux" ]; then
			paplay ${BARK_PATH}
		else
			# for osx
			afplay /System/Library/Sounds/Ping.aiff
		fi
	done
}

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

notify "PR $PR_ID checks terminated" "Result: $result\nSee $base_url for more details."
