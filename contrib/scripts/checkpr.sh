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
	echo -e "\t-s\twatch Smoke Tests instead of Jenkins"
}

notif_audio=1
notif_desktop=1
smoke_tests=0
OPTIND=1
while getopts "hmqs" opt; do
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
		s)
			smoke_tests=1
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

is_true() {
	if [ $1 == "true" ]; then
		return 0
	else
		return 1
	fi
}

check_smoke_test() {
	PR_ID=$1

	# Get branch (HEAD) for PR
	BRANCH=$(curl -s "https://api.github.com/repos/cilium/cilium/pulls/$PR_ID" | jq -r '.head.ref')

	# Get workflow ID for latest Smoke tests run for that branch
	ID=$(curl -s "https://api.github.com/repos/cilium/cilium/actions/workflows/smoke-test.yaml/runs?branch=$BRANCH&per_page=1" | jq '.workflow_runs[].id');

	while true; do
		# Get info for jobs in the Smoke tests workflow run
		OVERVIEW=$(curl -s "https://api.github.com/repos/cilium/cilium/actions/runs/$ID/jobs" | jq '[.jobs[]|{name: .name, status: .status, conclusion: .conclusion}]')
		date
		echo $OVERVIEW | jq

		STATUS=$(echo $OVERVIEW | jq '[.[]|.status == "completed"]|all')
		if $(is_true $STATUS); then
			CONCLUSION=$(echo $OVERVIEW | jq '[.[]|.conclusion == "success"]|all')
			if $(is_true $CONCLUSION); then
				RESULT="PASS ✔️"
			else
				RESULT="FAIL ❌"
			fi
			notify "Smoke tests for #$PR_ID finished" "Result: $RESULT\nhttps://github.com/cilium/cilium/pull/$PR_ID"
			break
		fi
		sleep 60
	done
}

if [ $smoke_tests -eq 1 ]; then
	check_smoke_test $1
fi
