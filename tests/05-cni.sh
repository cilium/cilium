#!/bin/bash

export PATH=$PATH:/opt/cni/bin

source "./helpers.bash"
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

server_id=""
client_id=""

logs_clear

set -e

function run_cni_container {
	LABELS=""
	ARGS=""

	while [[ $# != 0 ]]; do
		if [ "$1" == "-l" -o "$1" == "--label" ]; then
			LABELS="$LABELS -l $2"
		fi
		ARGS="$ARGS $1"
		shift
	done

	contid=$(docker run -t -d --net=none $LABELS busybox:latest)
	pid=$(docker inspect -f '{{ .State.Pid }}' $contid)
	netnspath=/proc/$pid/ns/net

	sudo -E PATH=$PATH:/opt/cni/bin ./exec-plugins.sh add $contid $netnspath

	docker run --net=container:$contid $ARGS > /dev/null

	echo $contid
}

function kill_cni_container {
	if [ ! -z "$1" ]; then
		pid=$(docker inspect -f '{{ .State.Pid }}' $1)
		netnspath=/proc/$pid/ns/net

		sudo -E PATH=$PATH:/opt/cni/bin ./exec-plugins.sh del $1 $netnspath
		docker rm -f $1 >/dev/null
	fi

	clean_container $2
}

function extract_ip4 {
	docker exec -i $1 ip -4 a show dev eth0 scope global | grep inet | sed -e 's%.*inet \(.*\)\/.*%\1%'
}

function extract_ip6 {
	docker exec -i $1 ip -6 a show dev eth0 scope global | grep inet6 | sed -e 's%.*inet6 \(.*\)\/.*%\1%'
}

function clean_container {
	docker rm -f $1 2> /dev/null || true
}

function cleanup {
  cilium policy delete --all 2> /dev/null || true
  kill_cni_container $server_id cni-server || true
  kill_cni_container $client_id cni-client || true
  monitor_stop
  rm -rf $DIR
}

function finish_test {
  gather_files 05-cni ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT
cleanup

clean_container cni-server
clean_container cni-client
DIR=$(mktemp -d)
cd $DIR

monitor_start

cilium policy delete --all 2> /dev/null || true
cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"id.server":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"id.client":""}}
	]
    }]
}]
EOF

mkdir net.d
cat > net.d/10-cilium-cni.conf <<EOF
{
	"name": "cilium",
	"type": "cilium-cni",
	"mtu": 1450
}
EOF
export NETCONFPATH=`pwd`/net.d

git clone 'https://github.com/containernetworking/cni'
cd cni
git checkout tags/v0.5.2
./build.sh
export CNI_PATH=`pwd`/bin
cp "${dir}/../plugins/cilium-cni/cilium-cni" "${CNI_PATH}"
cd scripts

server_id=$(run_cni_container -d -l id.server --name cni-server tgraf/netperf)
client_id=$(run_cni_container -d -l id.client --name cni-client tgraf/netperf)

server_ip=$(extract_ip6 $server_id)
server_ip4=$(extract_ip4 $server_id)

echo "Waiting for containers to come up"
while true; do
    output=`docker ps -a`

    if echo ${output} | grep cni-server && \
        echo ${output} | grep cni-client; then
        break
    fi
done

monitor_clear
docker exec -i cni-client ping6 -c 10 $server_ip
monitor_clear
if [ $server_ip4 ]; then
	docker exec -i cni-client ping -c 10 $server_ip4
fi
