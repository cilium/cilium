#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

function abort {
	set +x

	echo "------------------------------------------------------------------------"
	echo "                          K8s Test Failed"
	echo "$*"
	echo ""
	echo "------------------------------------------------------------------------"

	cilium_id=$(docker ps -aq --filter=name=cilium-agent)
	echo "------------------------------------------------------------------------"
	echo "                            Cilium logs"
	docker logs ${cilium_id}
	echo ""
	echo "------------------------------------------------------------------------"

	exit 1
}
